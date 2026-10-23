/* zero-copy message codec for the BitTorrent peer wire protocol */

use crate::peer::PeerWireError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/* message identifier codes defined in BEP-0003 */
pub const MESSAGE_ID_CHOKE: u8 = 0;
pub const MESSAGE_ID_UNCHOKE: u8 = 1;
pub const MESSAGE_ID_INTERESTED: u8 = 2;
pub const MESSAGE_ID_NOT_INTERESTED: u8 = 3;
pub const MESSAGE_ID_HAVE: u8 = 4;
pub const MESSAGE_ID_BITFIELD: u8 = 5;
pub const MESSAGE_ID_REQUEST: u8 = 6;
pub const MESSAGE_ID_PIECE: u8 = 7;
pub const MESSAGE_ID_CANCEL: u8 = 8;
/* identify BEP-0010 extension protocol message */
pub const MESSAGE_ID_EXTENDED: u8 = 20;

/* safety limit preventing denial-of-service allocations from malformed lengths (2 MiB) */
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

/* wire messages exchanged across an established peer wire connection */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    /* 0-byte keep-alive ping sent periodically to keep TCP socket active */
    KeepAlive,
    /* tells recipient that sender will not fulfill incoming requests */
    Choke,
    /* tells recipient that sender is ready to accept incoming block requests */
    Unchoke,
    /* notifies peer of download interest in their advertised pieces */
    Interested,
    /* notifies peer that sender has no interest in their advertised pieces */
    NotInterested,
    /* advertises that sender successfully downloaded and verified a specific piece */
    Have {
        piece_index: u32,
    },
    /* zero-copy bitfield representing entire availability mask of pieces */
    Bitfield {
        bitfield: Bytes,
    },
    /* requests 16 KiB block from remote peer */
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    /* delivers 16 KiB block with zero-copy reference to memory buffer */
    Piece {
        index: u32,
        begin: u32,
        block: Bytes,
    },
    /* cancels previously queued block request */
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    /* deliver BEP-0010 extension protocol message carrying extended message ID and payload */
    Extended {
        extended_id: u8,
        payload: Bytes,
    },
}

/* stateful framed codec implementing zero-copy message decoding and encoding */
#[derive(Debug, Default)]
pub struct PeerWireCodec;

impl PeerWireCodec {
    /* instantiate clean peer wire codec */
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for PeerWireCodec {
    type Item = PeerMessage;
    type Error = PeerWireError;

    /* decode framed peer wire message from incoming byte buffer.
       wire frame layout:
       - 0..4: 4-byte big-endian message length prefix
       - 4:    1-byte message ID (absent if length == 0)
       - 5..N: variable payload (absent if length <= 1) */
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        /* check if the 4-byte length prefix has arrived */
        if src.len() < 4 {
            return Ok(None);
        }

        /* inspect length prefix in big-endian network byte order without consuming bytes */
        let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;

        /* guard against memory exhaustion from corrupt or malicious frames */
        if length > MAX_MESSAGE_SIZE {
            return Err(PeerWireError::MessageTooLarge(length));
        }

        /* handle 0-length keep-alive frame */
        if length == 0 {
            src.advance(4);
            return Ok(Some(PeerMessage::KeepAlive));
        }

        /* verify that the entire frame (4-byte length header + payload) is present */
        if src.len() < 4 + length {
            /* reserve additional buffer capacity to allow tokio to read remaining frame in one syscall */
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        /* consume 4-byte length header */
        src.advance(4);

        /* zero-copy slice payload from buffer; split_to increments buffer reference count */
        let mut payload = src.split_to(length);

        /* consume 1-byte message ID */
        let message_id = payload.split_to(1)[0];

        match message_id {
            MESSAGE_ID_CHOKE => Ok(Some(PeerMessage::Choke)),
            MESSAGE_ID_UNCHOKE => Ok(Some(PeerMessage::Unchoke)),
            MESSAGE_ID_INTERESTED => Ok(Some(PeerMessage::Interested)),
            MESSAGE_ID_NOT_INTERESTED => Ok(Some(PeerMessage::NotInterested)),
            MESSAGE_ID_HAVE => {
                if payload.len() != 4 {
                    return Err(PeerWireError::InvalidPayloadLength {
                        expected: 4,
                        actual: payload.len(),
                    });
                }
                let piece_index = u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                Ok(Some(PeerMessage::Have { piece_index }))
            }
            MESSAGE_ID_BITFIELD => {
                /* freeze remaining BytesMut into zero-copy immutable Bytes */
                Ok(Some(PeerMessage::Bitfield {
                    bitfield: payload.freeze(),
                }))
            }
            MESSAGE_ID_REQUEST => {
                if payload.len() != 12 {
                    return Err(PeerWireError::InvalidPayloadLength {
                        expected: 12,
                        actual: payload.len(),
                    });
                }
                let index = u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                let begin = u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]);
                let length = u32::from_be_bytes([
                    payload[8], payload[9], payload[10], payload[11],
                ]);
                Ok(Some(PeerMessage::Request {
                    index,
                    begin,
                    length,
                }))
            }
            MESSAGE_ID_PIECE => {
                if payload.len() < 8 {
                    return Err(PeerWireError::InvalidPayloadLength {
                        expected: 8,
                        actual: payload.len(),
                    });
                }
                let index = u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                let begin = u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]);
                /* advance cursor past the 8-byte index and offset header; remainder is zero-copy block */
                payload.advance(8);
                let block = payload.freeze();

                Ok(Some(PeerMessage::Piece {
                    index,
                    begin,
                    block,
                }))
            }
            MESSAGE_ID_CANCEL => {
                if payload.len() != 12 {
                    return Err(PeerWireError::InvalidPayloadLength {
                        expected: 12,
                        actual: payload.len(),
                    });
                }
                let index = u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                let begin = u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]);
                let length = u32::from_be_bytes([
                    payload[8], payload[9], payload[10], payload[11],
                ]);
                Ok(Some(PeerMessage::Cancel {
                    index,
                    begin,
                    length,
                }))
            }
            MESSAGE_ID_EXTENDED => {
                if payload.is_empty() {
                    return Err(PeerWireError::InvalidPayloadLength {
                        expected: 1,
                        actual: 0,
                    });
                }
                let extended_id = payload.split_to(1)[0];
                let extended_payload = payload.freeze();
                Ok(Some(PeerMessage::Extended {
                    extended_id,
                    payload: extended_payload,
                }))
            }
            unknown_id => Err(PeerWireError::UnknownMessageId(unknown_id)),
        }
    }
}

impl Encoder<PeerMessage> for PeerWireCodec {
    type Error = PeerWireError;

    /* serialize PeerMessage into destination BytesMut buffer using big-endian framing */
    fn encode(&mut self, item: PeerMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            PeerMessage::KeepAlive => {
                /* 4-byte 0 length */
                dst.put_u32(0);
            }
            PeerMessage::Choke => {
                dst.put_u32(1);
                dst.put_u8(MESSAGE_ID_CHOKE);
            }
            PeerMessage::Unchoke => {
                dst.put_u32(1);
                dst.put_u8(MESSAGE_ID_UNCHOKE);
            }
            PeerMessage::Interested => {
                dst.put_u32(1);
                dst.put_u8(MESSAGE_ID_INTERESTED);
            }
            PeerMessage::NotInterested => {
                dst.put_u32(1);
                dst.put_u8(MESSAGE_ID_NOT_INTERESTED);
            }
            PeerMessage::Have { piece_index } => {
                dst.put_u32(5);
                dst.put_u8(MESSAGE_ID_HAVE);
                dst.put_u32(piece_index);
            }
            PeerMessage::Bitfield { bitfield } => {
                dst.put_u32(1 + bitfield.len() as u32);
                dst.put_u8(MESSAGE_ID_BITFIELD);
                dst.extend_from_slice(&bitfield);
            }
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                dst.put_u32(13);
                dst.put_u8(MESSAGE_ID_REQUEST);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                dst.put_u32(9 + block.len() as u32);
                dst.put_u8(MESSAGE_ID_PIECE);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.extend_from_slice(&block);
            }
            PeerMessage::Cancel {
                index,
                begin,
                length,
            } => {
                dst.put_u32(13);
                dst.put_u8(MESSAGE_ID_CANCEL);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            PeerMessage::Extended {
                extended_id,
                payload,
            } => {
                dst.put_u32(2 + payload.len() as u32);
                dst.put_u8(MESSAGE_ID_EXTENDED);
                dst.put_u8(extended_id);
                dst.extend_from_slice(&payload);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_keepalive_roundtrip() {
        let mut codec = PeerWireCodec::new();
        let mut buffer = BytesMut::new();

        codec.encode(PeerMessage::KeepAlive, &mut buffer).unwrap();
        assert_eq!(&buffer[..], &[0, 0, 0, 0]);

        let decoded = codec.decode(&mut buffer).unwrap();
        assert_eq!(decoded, Some(PeerMessage::KeepAlive));
    }

    #[test]
    fn test_codec_piece_zero_copy_roundtrip() {
        let mut codec = PeerWireCodec::new();
        let mut buffer = BytesMut::new();

        let raw_block = Bytes::from_static(b"zero copy block contents for piece test");
        let piece_msg = PeerMessage::Piece {
            index: 42,
            begin: 16384,
            block: raw_block.clone(),
        };

        codec.encode(piece_msg, &mut buffer).unwrap();

        /* verify wire layout: length (9 + len), ID (7), index (42), begin (16384), data */
        let expected_len = 9 + raw_block.len();
        assert_eq!(&buffer[0..4], &(expected_len as u32).to_be_bytes());
        assert_eq!(buffer[4], MESSAGE_ID_PIECE);

        let decoded = codec.decode(&mut buffer).unwrap().expect("message decoded");
        match decoded {
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                assert_eq!(index, 42);
                assert_eq!(begin, 16384);
                assert_eq!(block, raw_block);
            }
            other => panic!("expected Piece message, got: {:?}", other),
        }
    }

    #[test]
    fn test_codec_request_roundtrip() {
        let mut codec = PeerWireCodec::new();
        let mut buffer = BytesMut::new();

        let req = PeerMessage::Request {
            index: 10,
            begin: 32768,
            length: 16384,
        };

        codec.encode(req.clone(), &mut buffer).unwrap();
        let decoded = codec.decode(&mut buffer).unwrap().expect("request decoded");
        assert_eq!(decoded, req);
    }
}
