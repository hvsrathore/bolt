/* manage PeerSession actor maintaining 32 in-flight 16 KiB block requests and piece reassembly */

use crate::peer::codec::{PeerMessage, PeerWireCodec};
use crate::peer::{Handshake, PeerWireError};
use crate::sha1::Sha1;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashSet, VecDeque};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

/* maximum number of concurrent in-flight block requests (sliding window of 32 requests) */
pub const PIPELINE_CAPACITY_32: usize = 32;

/* nominal block chunk size defined across the BitTorrent ecosystem (16 KiB = 16,384 bytes) */
pub const BLOCK_SIZE_16KIB: u32 = 16 * 1024;

/* discrete 16 KiB sub-piece block request unit */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockRequest {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}

/* verified, fully reassembled piece ready for memory or storage consumption */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledPiece {
    pub index: u32,
    pub data: Vec<u8>,
}

/* in-memory piece reassembly state accumulating out-of-order 16 KiB block payloads */
#[derive(Debug)]
pub struct PieceReassembly {
    pub index: u32,
    pub piece_length: u32,
    pub expected_hash: [u8; 20],
    pub buffer: Vec<u8>,
    pub blocks_received: usize,
    pub total_blocks: usize,
    pub received_blocks: Vec<bool>,
}

impl PieceReassembly {
    /* instantiate piece buffer and block tracking bitmap for piece length */
    pub fn new(index: u32, piece_length: u32, expected_hash: [u8; 20]) -> Self {
        let total_blocks = piece_length.div_ceil(BLOCK_SIZE_16KIB) as usize;
        Self {
            index,
            piece_length,
            expected_hash,
            buffer: vec![0u8; piece_length as usize],
            blocks_received: 0,
            total_blocks,
            received_blocks: vec![false; total_blocks],
        }
    }

    /* write incoming block payload at byte offset begin, returning true if piece is complete */
    pub fn write_block(&mut self, begin: u32, data: &[u8]) -> Result<bool, PeerWireError> {
        let end = begin as usize + data.len();
        if end > self.piece_length as usize {
            return Err(PeerWireError::InvalidBlockBounds {
                index: self.index,
                begin,
                length: data.len() as u32,
            });
        }

        /* determine block index in bitmap */
        let block_idx = (begin / BLOCK_SIZE_16KIB) as usize;
        if block_idx >= self.total_blocks {
            return Err(PeerWireError::InvalidBlockBounds {
                index: self.index,
                begin,
                length: data.len() as u32,
            });
        }

        /* copy block bytes directly into designated region of piece buffer */
        self.buffer[begin as usize..end].copy_from_slice(data);

        /* update block receipt accounting */
        if !self.received_blocks[block_idx] {
            self.received_blocks[block_idx] = true;
            self.blocks_received += 1;
        }

        Ok(self.blocks_received == self.total_blocks)
    }

    /* verify SHA-1 cryptographic digest of reassembled buffer against metainfo expectation */
    pub fn verify_hash(&self) -> bool {
        let digest = Sha1::digest(&self.buffer);
        digest == self.expected_hash
    }
}

/* events produced by PeerSession during wire communication */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /* remote peer sent Bitfield message */
    BitfieldReceived(Bytes),
    /* remote peer advertised availability of piece via Have message */
    HaveReceived(u32),
    /* connection choke/interest state shifted */
    StateChanged {
        peer_choking: bool,
        am_interested: bool,
    },
    /* piece completely downloaded and verified against its cryptographic SHA-1 hash */
    PieceCompleted(AssembledPiece),
    /* handle BEP-0010 extension protocol message received from remote peer */
    ExtendedReceived {
        extended_id: u8,
        payload: Bytes,
    },
}

/* commands accepted by asynchronous PeerSession actor handle */
#[derive(Debug)]
pub enum SessionCommand {
    /* queue piece for download */
    QueuePiece {
        index: u32,
        length: u32,
        expected_hash: [u8; 20],
    },
    /* instruct session to send Interested message */
    ExpressInterest,
    /* instruct session to gracefully disconnect */
    Terminate,
}

/* peer session actor maintaining protocol state, flow control, and 32 in-flight block requests */
pub struct PeerSession<S> {
    framed: Framed<S, PeerWireCodec>,
    /* flow control state tracking */
    pub peer_choking: bool,
    pub peer_interested: bool,
    pub am_choking: bool,
    pub am_interested: bool,
    /* peer advertised bitfield */
    pub peer_bitfield: Option<Bytes>,
    /* in-flight block requests awaiting Piece response from remote peer */
    pub in_flight: HashSet<BlockRequest>,
    /* internal FIFO queue of block requests awaiting transmission */
    pub pending_blocks: VecDeque<BlockRequest>,
    /* active in-memory piece reassembly buffer */
    pub active_piece: Option<PieceReassembly>,
}

impl<S> PeerSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /* construct new PeerSession over established async stream with standard choked initial state */
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, PeerWireCodec::new()),
            peer_choking: true,
            peer_interested: false,
            am_choking: true,
            am_interested: false,
            peer_bitfield: None,
            in_flight: HashSet::with_capacity(PIPELINE_CAPACITY_32),
            pending_blocks: VecDeque::new(),
            active_piece: None,
        }
    }

    /* execute initial wire handshake exchange prior to frame streaming */
    pub async fn handshake(
        &mut self,
        local_handshake: &Handshake,
        expected_info_hash: Option<[u8; 20]>,
    ) -> Result<Handshake, PeerWireError> {
        let stream = self.framed.get_mut();
        Handshake::exchange(stream, local_handshake, expected_info_hash).await
    }

    /* enqueue piece to be partitioned into 16 KiB block requests and reassembled */
    pub fn queue_piece(&mut self, index: u32, length: u32, expected_hash: [u8; 20]) {
        self.active_piece = Some(PieceReassembly::new(index, length, expected_hash));

        /* slice entire piece into sequential 16 KiB block requests */
        let mut begin = 0;
        while begin < length {
            let block_len = std::cmp::min(BLOCK_SIZE_16KIB, length - begin);
            self.pending_blocks.push_back(BlockRequest {
                index,
                begin,
                length: block_len,
            });
            begin += block_len;
        }
    }

    /* replenish in-flight pipeline up to 32 requests whenever unchoked.
       pipelining 32 requests of 16 KiB creates a 512 KiB in-flight sliding window.
       this prevents bandwidth-delay product starvation over high-latency networks */
    pub async fn replenish_pipeline(&mut self) -> Result<usize, PeerWireError> {
        /* requests cannot be dispatched while peer is choking our client */
        if self.peer_choking {
            return Ok(0);
        }

        let mut dispatched = 0;
        while self.in_flight.len() < PIPELINE_CAPACITY_32 {
            if let Some(req) = self.pending_blocks.pop_front() {
                /* transmit Request frame over TCP socket */
                self.framed
                    .send(PeerMessage::Request {
                        index: req.index,
                        begin: req.begin,
                        length: req.length,
                    })
                    .await?;

                self.in_flight.insert(req);
                dispatched += 1;
            } else {
                break;
            }
        }

        Ok(dispatched)
    }

    /* express download interest to remote peer if not already flagged */
    pub async fn send_interested(&mut self) -> Result<(), PeerWireError> {
        if !self.am_interested {
            self.framed.send(PeerMessage::Interested).await?;
            self.am_interested = true;
        }
        Ok(())
    }

    /* transmit BEP-0010 extension protocol message */
    pub async fn send_extended(
        &mut self,
        extended_id: u8,
        payload: Bytes,
    ) -> Result<(), PeerWireError> {
        self.framed
            .send(PeerMessage::Extended {
                extended_id,
                payload,
            })
            .await
    }

    /* process single incoming wire message and update pipeline state */
    pub async fn step(&mut self) -> Result<Option<SessionEvent>, PeerWireError> {
        let message = match self.framed.next().await {
            Some(res) => res?,
            None => return Err(PeerWireError::ConnectionClosed),
        };

        match message {
            PeerMessage::KeepAlive => {
                /* keep-alive received; connection remains healthy */
                Ok(None)
            }
            PeerMessage::Choke => {
                /* peer choked client: unfulfilled in-flight requests are dropped by remote peer */
                self.peer_choking = true;

                /* return all orphaned in-flight requests to the front of the pending queue */
                for req in self.in_flight.drain() {
                    self.pending_blocks.push_front(req);
                }

                Ok(Some(SessionEvent::StateChanged {
                    peer_choking: true,
                    am_interested: self.am_interested,
                }))
            }
            PeerMessage::Unchoke => {
                /* peer unchoked client: immediately fill the pipeline up to 32 requests */
                self.peer_choking = false;

                /* ensure interest is signaled */
                self.send_interested().await?;

                /* fill the 32 in-flight request pipeline */
                self.replenish_pipeline().await?;

                Ok(Some(SessionEvent::StateChanged {
                    peer_choking: false,
                    am_interested: self.am_interested,
                }))
            }
            PeerMessage::Interested => {
                self.peer_interested = true;
                Ok(None)
            }
            PeerMessage::NotInterested => {
                self.peer_interested = false;
                Ok(None)
            }
            PeerMessage::Have { piece_index } => Ok(Some(SessionEvent::HaveReceived(piece_index))),
            PeerMessage::Bitfield { bitfield } => {
                self.peer_bitfield = Some(bitfield.clone());
                Ok(Some(SessionEvent::BitfieldReceived(bitfield)))
            }
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                /* retire matching block request from in-flight tracker */
                let req_key = BlockRequest {
                    index,
                    begin,
                    length: block.len() as u32,
                };
                self.in_flight.remove(&req_key);

                /* write payload into active reassembly buffer */
                let completed_event = if let Some(ref mut reassembly) = self.active_piece {
                    if reassembly.index == index {
                        let is_complete = reassembly.write_block(begin, &block)?;
                        if is_complete {
                            /* verify SHA-1 cryptographic digest */
                            if !reassembly.verify_hash() {
                                return Err(PeerWireError::PieceHashMismatch { index });
                            }

                            let assembled = AssembledPiece {
                                index: reassembly.index,
                                data: std::mem::take(&mut reassembly.buffer),
                            };
                            Some(SessionEvent::PieceCompleted(assembled))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                /* keep the 32 in-flight request pipeline saturated */
                self.replenish_pipeline().await?;

                Ok(completed_event)
            }
            PeerMessage::Request { .. } => {
                /* baseline seeder response: client behaves as active leecher */
                Ok(None)
            }
            PeerMessage::Cancel { .. } => Ok(None),
            PeerMessage::Extended {
                extended_id,
                payload,
            } => Ok(Some(SessionEvent::ExtendedReceived {
                extended_id,
                payload,
            })),
        }
    }
}

/* handle to communicate asynchronously with a spawned PeerSession actor */
pub struct PeerSessionHandle {
    command_tx: mpsc::Sender<SessionCommand>,
}

impl PeerSessionHandle {
    /* queue piece download via command channel */
    pub async fn queue_piece(
        &self,
        index: u32,
        length: u32,
        expected_hash: [u8; 20],
    ) -> Result<(), mpsc::error::SendError<SessionCommand>> {
        self.command_tx
            .send(SessionCommand::QueuePiece {
                index,
                length,
                expected_hash,
            })
            .await
    }

    /* instruct session to disconnect */
    pub async fn terminate(&self) -> Result<(), mpsc::error::SendError<SessionCommand>> {
        self.command_tx.send(SessionCommand::Terminate).await
    }
}

/* spawn asynchronous actor task managing peer wire event loop */
pub fn spawn_peer_session<S>(
    mut session: PeerSession<S>,
) -> (PeerSessionHandle, mpsc::Receiver<SessionEvent>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCommand>(64);
    let (event_tx, event_rx) = mpsc::channel::<SessionEvent>(64);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                /* process inbound commands */
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        SessionCommand::QueuePiece { index, length, expected_hash } => {
                            session.queue_piece(index, length, expected_hash);
                            let _ = session.replenish_pipeline().await;
                        }
                        SessionCommand::ExpressInterest => {
                            let _ = session.send_interested().await;
                        }
                        SessionCommand::Terminate => {
                            break;
                        }
                    }
                }
                /* process inbound wire frames from stream */
                step_res = session.step() => {
                    match step_res {
                        Ok(Some(event)) => {
                            if event_tx.send(event).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        }
    });

    (PeerSessionHandle { command_tx: cmd_tx }, event_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha1::Sha1;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_handshake_and_32_pipeline_block_requests() {
        /* setup bidirectional in-memory duplex streams */
        let (client_stream, server_stream) = duplex(65536);

        let info_hash = [0x42u8; 20];
        let client_peer_id = [0x01u8; 20];
        let server_peer_id = [0x02u8; 20];

        let mut client_session = PeerSession::new(client_stream);

        /* spawn server task performing handshake and verifying 32 block requests */
        let server_task = tokio::spawn(async move {
            let mut server_framed = Framed::new(server_stream, PeerWireCodec::new());

            /* exchange handshake */
            let server_handshake = Handshake::new(info_hash, server_peer_id);
            let client_handshake = Handshake::exchange(
                server_framed.get_mut(),
                &server_handshake,
                Some(info_hash),
            )
            .await
            .expect("server handshake failed");
            assert_eq!(client_handshake.peer_id, client_peer_id);

            /* send Unchoke to client */
            server_framed
                .send(PeerMessage::Unchoke)
                .await
                .expect("send unchoke failed");

            /* read client Interested message */
            let msg1 = server_framed.next().await.unwrap().unwrap();
            assert_eq!(msg1, PeerMessage::Interested);

            /* verify client immediately dispatches exactly 32 in-flight block requests */
            let mut received_requests = Vec::new();
            for _ in 0..PIPELINE_CAPACITY_32 {
                let req_msg = server_framed.next().await.unwrap().unwrap();
                match req_msg {
                    PeerMessage::Request {
                        index,
                        begin,
                        length,
                    } => {
                        received_requests.push((index, begin, length));
                    }
                    other => panic!("expected Request message, got: {:?}", other),
                }
            }

            assert_eq!(received_requests.len(), 32);
            /* verify first block request has index 0, begin 0, length 16 KiB */
            assert_eq!(received_requests[0], (0, 0, BLOCK_SIZE_16KIB));
            /* verify second block request has begin 16384 */
            assert_eq!(received_requests[1], (0, 16384, BLOCK_SIZE_16KIB));
        });

        /* client performs handshake */
        let client_handshake = Handshake::new(info_hash, client_peer_id);
        let remote_hs = client_session
            .handshake(&client_handshake, Some(info_hash))
            .await
            .expect("client handshake failed");
        assert_eq!(remote_hs.peer_id, server_peer_id);

        /* queue piece of size 1 MiB (64 blocks of 16 KiB) */
        let dummy_hash = [0x99u8; 20];
        client_session.queue_piece(0, 1024 * 1024, dummy_hash);

        /* execute step: reads unchoke, dispatches 32 in-flight requests */
        let event = client_session.step().await.unwrap();
        assert_eq!(
            event,
            Some(SessionEvent::StateChanged {
                peer_choking: false,
                am_interested: true,
            })
        );
        assert_eq!(client_session.in_flight.len(), PIPELINE_CAPACITY_32);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_piece_reassembly_and_hash_validation() {
        let (client_stream, server_stream) = duplex(65536);

        /* construct synthetic 64 KiB piece (4 blocks of 16 KiB) */
        let piece_len = 64 * 1024;
        let mut full_piece_data = Vec::with_capacity(piece_len);
        for i in 0..piece_len {
            full_piece_data.push((i % 251) as u8);
        }
        let expected_hash = Sha1::digest(&full_piece_data);

        let mut client_session = PeerSession::new(client_stream);
        client_session.queue_piece(5, piece_len as u32, expected_hash);
        client_session.peer_choking = false; /* simulate unchoked */

        /* spawn server task feeding 4 Piece messages in arbitrary order */
        let piece_bytes = full_piece_data.clone();
        let server_task = tokio::spawn(async move {
            let mut server_framed = Framed::new(server_stream, PeerWireCodec::new());

            /* read 4 requests dispatched by client */
            for _ in 0..4 {
                let _ = server_framed.next().await.unwrap().unwrap();
            }

            /* serve blocks 0, 1, 2, 3 */
            for block_idx in 0..4 {
                let begin = (block_idx * BLOCK_SIZE_16KIB) as usize;
                let block_slice = &piece_bytes[begin..begin + BLOCK_SIZE_16KIB as usize];
                let piece_msg = PeerMessage::Piece {
                    index: 5,
                    begin: begin as u32,
                    block: Bytes::copy_from_slice(block_slice),
                };
                server_framed.send(piece_msg).await.unwrap();
            }
        });

        /* trigger pipeline replenishment */
        client_session.replenish_pipeline().await.unwrap();
        assert_eq!(client_session.in_flight.len(), 4);

        /* step through first 3 blocks */
        for _ in 0..3 {
            let ev = client_session.step().await.unwrap();
            assert_eq!(ev, None);
        }

        /* 4th block completes piece and verifies SHA-1 digest */
        let final_ev = client_session.step().await.unwrap();
        match final_ev {
            Some(SessionEvent::PieceCompleted(assembled)) => {
                assert_eq!(assembled.index, 5);
                assert_eq!(assembled.data, full_piece_data);
            }
            other => panic!("expected PieceCompleted event, got: {:?}", other),
        }

        server_task.await.unwrap();
    }
}
