/* central SwarmCoordinator tracking peer bitfields, Rarest-First selection, and Endgame Mode */

use crate::peer::codec::PeerMessage;
use crate::peer::session::{AssembledPiece, BLOCK_SIZE_16KIB};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};

/* discrete key uniquely identifying a 16 KiB block within global torrent */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockKey {
    pub piece_index: u32,
    pub begin: u32,
    pub length: u32,
}

/* cancellation directive dispatched to remote peer to terminate redundant in-flight request */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCancelDirective {
    pub peer_id: usize,
    pub piece_index: u32,
    pub begin: u32,
    pub length: u32,
}

/* in-progress piece download state tracking block completion */
#[derive(Debug)]
pub struct ActivePieceState {
    pub index: u32,
    pub piece_length: u32,
    pub total_blocks: usize,
    pub received_blocks: HashSet<u32>,
    pub block_data: HashMap<u32, Bytes>,
}

impl ActivePieceState {
    /* initialize tracking for piece partitioning into 16 KiB blocks */
    pub fn new(index: u32, piece_length: u32) -> Self {
        let total_blocks = piece_length.div_ceil(BLOCK_SIZE_16KIB) as usize;
        Self {
            index,
            piece_length,
            total_blocks,
            received_blocks: HashSet::with_capacity(total_blocks),
            block_data: HashMap::with_capacity(total_blocks),
        }
    }

    /* check if all constituent blocks have arrived */
    pub fn is_complete(&self) -> bool {
        self.received_blocks.len() == self.total_blocks
    }

    /* stitch out-of-order 16 KiB memory buffers into contiguous piece */
    pub fn assemble(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; self.piece_length as usize];
        for (&begin, data) in &self.block_data {
            let start = begin as usize;
            let end = start + data.len();
            buffer[start..end].copy_from_slice(data);
        }
        buffer
    }
}

/* central coordinator tracking swarm piece distribution and scheduling block requests */
pub struct SwarmCoordinator {
    piece_count: usize,
    piece_length: u32,
    total_length: u64,
    /* peer piece possession tracking (peer_id -> bit vector) */
    peer_bitfields: HashMap<usize, Vec<bool>>,
    /* piece availability histogram across connected swarm */
    piece_rarity: Vec<usize>,
    /* flags indicating verified on-disk pieces */
    pieces_completed: Vec<bool>,
    /* active partially-downloaded pieces */
    active_pieces: HashMap<u32, ActivePieceState>,
    /* in-flight block tracking (block -> set of peers requested from) */
    in_flight: HashMap<BlockKey, HashSet<usize>>,
    /* endgame mode flag */
    pub is_endgame: bool,
    /* tie-breaker round-robin offset to prevent peer swarm request clustering */
    tie_breaker_counter: usize,
}

impl SwarmCoordinator {
    /* instantiate coordinator over torrent geometry metrics */
    pub fn new(piece_count: usize, piece_length: u32, total_length: u64) -> Self {
        Self {
            piece_count,
            piece_length,
            total_length,
            peer_bitfields: HashMap::new(),
            piece_rarity: vec![0; piece_count],
            pieces_completed: vec![false; piece_count],
            active_pieces: HashMap::new(),
            in_flight: HashMap::new(),
            is_endgame: false,
            tie_breaker_counter: 0,
        }
    }

    /* calculate byte size for given piece index, handling abbreviated final piece */
    pub fn piece_size(&self, piece_index: u32) -> u32 {
        let piece_start = piece_index as u64 * self.piece_length as u64;
        let remaining = self.total_length.saturating_sub(piece_start);
        std::cmp::min(self.piece_length as u64, remaining) as u32
    }

    /* register connected peer and initialize their bitfield */
    pub fn register_peer(&mut self, peer_id: usize) {
        self.peer_bitfields
            .entry(peer_id)
            .or_insert_with(|| vec![false; self.piece_count]);
    }

    /* deregister peer upon disconnection, decrementing availability histogram */
    pub fn unregister_peer(&mut self, peer_id: usize) {
        if let Some(bitfield) = self.peer_bitfields.remove(&peer_id) {
            for (piece_idx, &has_piece) in bitfield.iter().enumerate() {
                if has_piece {
                    self.piece_rarity[piece_idx] = self.piece_rarity[piece_idx].saturating_sub(1);
                }
            }
        }

        /* purge peer from in-flight block request tracker */
        for peers in self.in_flight.values_mut() {
            peers.remove(&peer_id);
        }
        self.in_flight.retain(|_, peers| !peers.is_empty());

        /* re-evaluate endgame mode conditions */
        self.check_endgame_transition();
    }

    /* record bitfield message received from peer and update swarm rarity counts */
    pub fn update_peer_bitfield(&mut self, peer_id: usize, raw_bitfield: &[u8]) {
        self.register_peer(peer_id);
        let bitfield = self.peer_bitfields.get_mut(&peer_id).unwrap();

        for (byte_idx, &byte) in raw_bitfield.iter().enumerate() {
            for bit_offset in 0..8 {
                let piece_idx = byte_idx * 8 + bit_offset;
                if piece_idx < self.piece_count {
                    let has_piece = (byte & (0x80 >> bit_offset)) != 0;
                    if has_piece && !bitfield[piece_idx] {
                        bitfield[piece_idx] = true;
                        self.piece_rarity[piece_idx] += 1;
                    }
                }
            }
        }
    }

    /* record Have message received from peer and increment piece availability */
    pub fn update_peer_have(&mut self, peer_id: usize, piece_index: u32) {
        self.register_peer(peer_id);
        let idx = piece_index as usize;
        if idx < self.piece_count {
            let bitfield = self.peer_bitfields.get_mut(&peer_id).unwrap();
            if !bitfield[idx] {
                bitfield[idx] = true;
                self.piece_rarity[idx] += 1;
            }
        }
    }

    /* select next piece index according to Rarest-First strategy.
       algorithm:
       1. filter incomplete pieces that the peer possesses and have non-zero rarity.
       2. sort candidate pieces by swarm availability ascending (rarest pieces first).
       3. break ties using a rotating offset counter to prevent peer request clustering */
    pub fn select_rarest_piece_for_peer(&mut self, peer_id: usize) -> Option<u32> {
        let bitfield = self.peer_bitfields.get(&peer_id)?;

        let mut candidates = Vec::new();
        for (piece_idx, &has_piece) in bitfield.iter().enumerate().take(self.piece_count) {
            if !self.pieces_completed[piece_idx]
                && !self.active_pieces.contains_key(&(piece_idx as u32))
                && has_piece
                && self.piece_rarity[piece_idx] > 0
            {
                candidates.push((self.piece_rarity[piece_idx], piece_idx));
            }
        }

        if candidates.is_empty() {
            return None;
        }

        /* sort by rarity count ascending */
        candidates.sort_by_key(|&(rarity, _)| rarity);

        /* identify subset of pieces sharing minimal rarity */
        let min_rarity = candidates[0].0;
        let tied_count = candidates
            .iter()
            .take_while(|&&(r, _)| r == min_rarity)
            .count();

        /* round-robin tie break to spread load across swarm */
        let selected_idx = self.tie_breaker_counter % tied_count;
        self.tie_breaker_counter = self.tie_breaker_counter.wrapping_add(1);

        Some(candidates[selected_idx].1 as u32)
    }

    /* calculate total remaining unreceived 16 KiB blocks across entire torrent */
    pub fn remaining_unreceived_blocks(&self) -> usize {
        let mut unreceived = 0;
        for piece_idx in 0..self.piece_count {
            if self.pieces_completed[piece_idx] {
                continue;
            }

            let piece_u32 = piece_idx as u32;
            let piece_size = self.piece_size(piece_u32);
            let total_blocks = piece_size.div_ceil(BLOCK_SIZE_16KIB) as usize;

            if let Some(active) = self.active_pieces.get(&piece_u32) {
                unreceived += total_blocks.saturating_sub(active.received_blocks.len());
            } else {
                unreceived += total_blocks;
            }
        }
        unreceived
    }

    /* inspect conditions and trigger Endgame Mode when all unreceived blocks are in-flight.
       endgame mode transition: when every single remaining unreceived block has been requested
       at least once, the download risk shifts from throughput maximization to tail-latency mitigation.
       a single slow peer or dropped packet on the final blocks can cause the entire torrent download
       to stall indefinitely. in endgame mode, unreceived blocks are aggressively duplicated across
       all available unchoked peers possessing the piece */
    pub fn check_endgame_transition(&mut self) {
        let unreceived = self.remaining_unreceived_blocks();
        let unique_in_flight = self.in_flight.len();

        if unreceived > 0 && unreceived == unique_in_flight {
            self.is_endgame = true;
        }
    }

    /* generate next batch of 16 KiB block requests for specified peer */
    pub fn next_requests_for_peer(
        &mut self,
        peer_id: usize,
        max_requests: usize,
    ) -> Vec<PeerMessage> {
        let mut requests = Vec::new();

        if self.is_endgame {
            /* endgame mode: duplicate unreceived block requests to this peer if available */
            if let Some(bitfield) = self.peer_bitfields.get(&peer_id) {
                for (&piece_idx, active) in &self.active_pieces {
                    if !bitfield[piece_idx as usize] {
                        continue;
                    }

                    let mut begin = 0;
                    while begin < active.piece_length {
                        let block_len = std::cmp::min(BLOCK_SIZE_16KIB, active.piece_length - begin);
                        if !active.received_blocks.contains(&begin) {
                            let key = BlockKey {
                                piece_index: piece_idx,
                                begin,
                                length: block_len,
                            };

                            /* only request if this specific peer has not yet been asked */
                            let peers = self.in_flight.entry(key).or_default();
                            if !peers.contains(&peer_id) {
                                peers.insert(peer_id);
                                requests.push(PeerMessage::Request {
                                    index: piece_idx,
                                    begin,
                                    length: block_len,
                                });

                                if requests.len() >= max_requests {
                                    return requests;
                                }
                            }
                        }
                        begin += block_len;
                    }
                }
            }
            return requests;
        }

        /* standard mode: prioritize blocks from existing active pieces */
        let active_keys: Vec<u32> = self.active_pieces.keys().copied().collect();
        for piece_idx in active_keys {
            if let Some(bitfield) = self.peer_bitfields.get(&peer_id)
                && !bitfield[piece_idx as usize]
            {
                continue;
            }

            let active = self.active_pieces.get(&piece_idx).unwrap();
            let mut begin = 0;
            while begin < active.piece_length {
                let block_len = std::cmp::min(BLOCK_SIZE_16KIB, active.piece_length - begin);
                let key = BlockKey {
                    piece_index: piece_idx,
                    begin,
                    length: block_len,
                };

                if !active.received_blocks.contains(&begin) && !self.in_flight.contains_key(&key) {
                    self.in_flight.entry(key).or_default().insert(peer_id);
                    requests.push(PeerMessage::Request {
                        index: piece_idx,
                        begin,
                        length: block_len,
                    });

                    if requests.len() >= max_requests {
                        self.check_endgame_transition();
                        return requests;
                    }
                }
                begin += block_len;
            }
        }

        /* if active pieces exhausted capacity, select new piece via Rarest-First */
        while requests.len() < max_requests {
            if let Some(piece_idx) = self.select_rarest_piece_for_peer(peer_id) {
                let piece_size = self.piece_size(piece_idx);
                let active = ActivePieceState::new(piece_idx, piece_size);
                self.active_pieces.insert(piece_idx, active);

                let mut begin = 0;
                while begin < piece_size {
                    let block_len = std::cmp::min(BLOCK_SIZE_16KIB, piece_size - begin);
                    let key = BlockKey {
                        piece_index: piece_idx,
                        begin,
                        length: block_len,
                    };

                    self.in_flight.entry(key).or_default().insert(peer_id);
                    requests.push(PeerMessage::Request {
                        index: piece_idx,
                        begin,
                        length: block_len,
                    });

                    begin += block_len;
                    if requests.len() >= max_requests {
                        self.check_endgame_transition();
                        return requests;
                    }
                }
            } else {
                break;
            }
        }

        self.check_endgame_transition();
        requests
    }

    /* process incoming block payload from peer.
       returns:
       - vector of Cancel directives for other peers that were asked for this block in Endgame Mode
       - optional AssembledPiece if this block completed all parts of the piece */
    pub fn on_block_received(
        &mut self,
        source_peer_id: usize,
        index: u32,
        begin: u32,
        block: Bytes,
    ) -> (Vec<PeerCancelDirective>, Option<AssembledPiece>) {
        let block_len = block.len() as u32;
        let key = BlockKey {
            piece_index: index,
            begin,
            length: block_len,
        };

        /* remove from in-flight tracker and collect other peers to cancel */
        let mut cancels = Vec::new();
        if let Some(peers) = self.in_flight.remove(&key) {
            for other_peer in peers {
                if other_peer != source_peer_id {
                    cancels.push(PeerCancelDirective {
                        peer_id: other_peer,
                        piece_index: index,
                        begin,
                        length: block_len,
                    });
                }
            }
        }

        /* write into active piece reassembly buffer */
        let mut completed_piece = None;
        if let Some(active) = self.active_pieces.get_mut(&index)
            && !active.received_blocks.contains(&begin)
        {
            active.received_blocks.insert(begin);
            active.block_data.insert(begin, block);

            if active.is_complete() {
                let assembled_data = active.assemble();
                completed_piece = Some(AssembledPiece {
                    index,
                    data: assembled_data,
                });
            }
        }

        /* if piece completed, finalize accounting */
        if let Some(ref piece) = completed_piece {
            self.active_pieces.remove(&index);
            self.pieces_completed[piece.index as usize] = true;
        }

        /* check if download is complete or still requires endgame */
        if self.remaining_unreceived_blocks() == 0 {
            self.is_endgame = false;
        } else {
            self.check_endgame_transition();
        }

        (cancels, completed_piece)
    }

    /* verify whether all torrent pieces have completed */
    pub fn is_download_complete(&self) -> bool {
        self.pieces_completed.iter().all(|&c| c)
    }

    /* return overall download completion percentage (0.0 to 100.0) */
    pub fn progress_percentage(&self) -> f64 {
        let completed = self.pieces_completed.iter().filter(|&&c| c).count();
        (completed as f64 / self.piece_count as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rarest_first_piece_selection() {
        /* setup coordinator with 4 pieces */
        let mut coord = SwarmCoordinator::new(4, 32768, 4 * 32768);

        /* peer 1 has pieces 0, 1, 2 */
        coord.register_peer(1);
        coord.update_peer_have(1, 0);
        coord.update_peer_have(1, 1);
        coord.update_peer_have(1, 2);

        /* peer 2 has pieces 0, 1 */
        coord.register_peer(2);
        coord.update_peer_have(2, 0);
        coord.update_peer_have(2, 1);

        /* peer 3 has piece 0 */
        coord.register_peer(3);
        coord.update_peer_have(3, 0);

        /* rarity histogram:
           piece 0: 3 peers (most common)
           piece 1: 2 peers
           piece 2: 1 peer  (rarest!)
           piece 3: 0 peers (unavailable) */

        /* peer 1 can provide piece 2, which is the rarest piece available */
        let selected = coord.select_rarest_piece_for_peer(1);
        assert_eq!(selected, Some(2));

        /* peer 2 does not have piece 2; its rarest available piece is piece 1 */
        let selected_p2 = coord.select_rarest_piece_for_peer(2);
        assert_eq!(selected_p2, Some(1));
    }

    #[test]
    fn test_endgame_mode_transition_and_cancels() {
        /* setup coordinator with 1 piece of 32 KiB (2 blocks of 16 KiB) */
        let mut coord = SwarmCoordinator::new(1, 32768, 32768);

        coord.register_peer(1);
        coord.update_peer_have(1, 0);

        coord.register_peer(2);
        coord.update_peer_have(2, 0);

        /* dispatch 1 request to peer 1 */
        let reqs1 = coord.next_requests_for_peer(1, 1);
        assert_eq!(reqs1.len(), 1);
        /* 1 block in flight out of 2 remaining: not yet endgame */
        assert!(!coord.is_endgame);

        /* dispatch 2nd request to peer 1 */
        let reqs2 = coord.next_requests_for_peer(1, 1);
        assert_eq!(reqs2.len(), 1);
        /* all 2 remaining blocks are now in flight: endgame mode activates */
        assert!(coord.is_endgame);

        /* when peer 2 asks for work, endgame duplicates the requests to peer 2 */
        let duplicate_reqs = coord.next_requests_for_peer(2, 2);
        assert_eq!(duplicate_reqs.len(), 2);

        /* block 0 arrives from peer 1 */
        let dummy_data = Bytes::from(vec![0x42; 16384]);
        let (cancels, completed) = coord.on_block_received(1, 0, 0, dummy_data);

        /* verify cancel was issued to peer 2 for block 0 */
        assert_eq!(cancels.len(), 1);
        assert_eq!(
            cancels[0],
            PeerCancelDirective {
                peer_id: 2,
                piece_index: 0,
                begin: 0,
                length: 16384,
            }
        );
        assert_eq!(completed, None);

        /* block 1 arrives from peer 2 */
        let dummy_data2 = Bytes::from(vec![0x43; 16384]);
        let (cancels2, completed2) = coord.on_block_received(2, 0, 16384, dummy_data2);

        /* verify cancel was issued to peer 1 for block 1 */
        assert_eq!(cancels2.len(), 1);
        assert_eq!(cancels2[0].peer_id, 1);
        assert!(completed2.is_some());

        assert!(coord.is_download_complete());
        assert!(!coord.is_endgame);
    }
}
