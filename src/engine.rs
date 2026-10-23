/* asynchronous BitTorrent swarm engine orchestrating trackers, peers, BEP-0009 metadata, and rarest-first downloads */

use crate::coordinator::SwarmCoordinator;
use crate::disk::DiskManager;
use crate::extensions::metadata::{MetadataReassembler, UtMetadataMessage};
use crate::extensions::{ExtendedHandshake, EXTENDED_HANDSHAKE_ID};
use crate::magnet::MagnetLink;
use crate::peer::codec::{PeerMessage, PeerWireCodec};
use crate::peer::session::PIPELINE_CAPACITY_32;
use crate::peer::Handshake;
use crate::sha1::Sha1;
use crate::torrent::{FileTree, Metainfo};
use crate::tracker::http::HttpTrackerClient;
use crate::tracker::udp::UdpTrackerClient;
use crate::tracker::{AnnounceEvent, AnnounceRequest, Peer};
use crate::ui::app::{AppState, PeerDisplayItem, PieceVisualState};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;
use tokio_util::codec::Framed;

/* maximum concurrent active peer TCP connections */
const MAX_CONCURRENT_PEERS: usize = 40;

/* peer TCP connection establishment timeout */
const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/* general peer wire message read timeout */
const PEER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/* generate pseudo-random 20-byte client peer_id prefixed with Azureus-style '-BL0100-' */
pub fn generate_peer_id() -> [u8; 20] {
    let mut peer_id = [0u8; 20];
    peer_id[..8].copy_from_slice(b"-BL0100-");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0x12345678);

    let mut state = nanos as u64;
    for slot in peer_id[8..].iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *slot = (state & 0xFF) as u8;
    }
    peer_id
}

/* active torrent engine state shared across background swarm tasks */
pub struct SwarmEngine {
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    trackers: Vec<String>,
    download_dir: PathBuf,
    app_state: Arc<Mutex<AppState>>,
    coordinator: Arc<tokio::sync::Mutex<Option<SwarmCoordinator>>>,
    disk_manager: Arc<tokio::sync::Mutex<Option<DiskManager>>>,
    expected_piece_hashes: Arc<tokio::sync::Mutex<Vec<[u8; 20]>>>,
    metadata_reassembler: Arc<tokio::sync::Mutex<Option<MetadataReassembler>>>,
    total_downloaded_bytes: Arc<AtomicU64>,
    total_uploaded_bytes: Arc<AtomicU64>,
    is_running: Arc<AtomicBool>,
}

impl SwarmEngine {
    /* instantiate new swarm engine from MagnetLink */
    pub fn new_from_magnet(
        magnet: &MagnetLink,
        app_state: Arc<Mutex<AppState>>,
        download_dir: PathBuf,
    ) -> Self {
        let peer_id = generate_peer_id();
        Self {
            info_hash: magnet.info_hash,
            peer_id,
            trackers: magnet.trackers.clone(),
            download_dir,
            app_state,
            coordinator: Arc::new(tokio::sync::Mutex::new(None)),
            disk_manager: Arc::new(tokio::sync::Mutex::new(None)),
            expected_piece_hashes: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            metadata_reassembler: Arc::new(tokio::sync::Mutex::new(None)),
            total_downloaded_bytes: Arc::new(AtomicU64::new(0)),
            total_uploaded_bytes: Arc::new(AtomicU64::new(0)),
            is_running: Arc::new(AtomicBool::new(true)),
        }
    }

    /* instantiate new swarm engine from parsed .torrent Metainfo */
    pub fn new_from_metainfo(
        metainfo: &Metainfo,
        app_state: Arc<Mutex<AppState>>,
        download_dir: PathBuf,
    ) -> Self {
        let peer_id = generate_peer_id();
        let piece_count = metainfo.piece_count();
        let piece_length = metainfo.piece_length;
        let total_length = metainfo.total_length();

        let mut expected_hashes = Vec::with_capacity(piece_count);
        for i in 0..piece_count {
            if let Some(hash) = metainfo.piece_hash(i) {
                expected_hashes.push(*hash);
            }
        }

        let coord = SwarmCoordinator::new(piece_count, piece_length as u32, total_length);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .ok();
        let dm = pool.and_then(|p| DiskManager::from_metainfo(&download_dir, metainfo, p).ok());

        let mut trackers = Vec::new();
        trackers.push(metainfo.announce.to_string());
        for tier in &metainfo.announce_list {
            for trk in tier {
                let s = trk.to_string();
                if !trackers.contains(&s) {
                    trackers.push(s);
                }
            }
        }

        Self {
            info_hash: metainfo.info_hash,
            peer_id,
            trackers,
            download_dir,
            app_state,
            coordinator: Arc::new(tokio::sync::Mutex::new(Some(coord))),
            disk_manager: Arc::new(tokio::sync::Mutex::new(dm)),
            expected_piece_hashes: Arc::new(tokio::sync::Mutex::new(expected_hashes)),
            metadata_reassembler: Arc::new(tokio::sync::Mutex::new(None)),
            total_downloaded_bytes: Arc::new(AtomicU64::new(0)),
            total_uploaded_bytes: Arc::new(AtomicU64::new(0)),
            is_running: Arc::new(AtomicBool::new(true)),
        }
    }

    /* stop background swarm operations */
    pub fn shutdown(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    /* check if background swarm engine is active */
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /* spawn asynchronous background engine tasks */
    pub fn start(self: Arc<Self>) {
        let (peer_tx, peer_rx) = mpsc::channel::<SocketAddr>(1000);

        /* 1. spawn tracker announce supervisor */
        let engine_clone = Arc::clone(&self);
        tokio::spawn(async move {
            engine_clone.run_tracker_announces(peer_tx).await;
        });

        /* 2. spawn peer connection and session manager */
        let engine_clone = Arc::clone(&self);
        tokio::spawn(async move {
            engine_clone.run_peer_manager(peer_rx).await;
        });

        /* 3. spawn throughput sparkline telemetry sampler */
        let engine_clone = Arc::clone(&self);
        tokio::spawn(async move {
            engine_clone.run_throughput_sampler().await;
        });
    }

    /* continuously announce to configured UDP and HTTP trackers in parallel */
    async fn run_tracker_announces(&self, peer_tx: mpsc::Sender<SocketAddr>) {
        let mut discovered = HashSet::new();

        while self.is_running.load(Ordering::SeqCst) {
            let mut join_set = tokio::task::JoinSet::new();

            for tracker_url in &self.trackers {
                if !self.is_running.load(Ordering::SeqCst) {
                    break;
                }

                let url = tracker_url.clone();
                let info_hash = self.info_hash;
                let peer_id = self.peer_id;
                let downloaded = self.total_downloaded_bytes.load(Ordering::Relaxed);
                let uploaded = self.total_uploaded_bytes.load(Ordering::Relaxed);

                let req = AnnounceRequest {
                    info_hash,
                    peer_id,
                    port: 6881,
                    uploaded,
                    downloaded,
                    left: 1024 * 1024 * 1024,
                    event: AnnounceEvent::Started,
                    num_want: Some(100),
                };

                join_set.spawn_blocking(move || -> Vec<Peer> {
                    if url.starts_with("udp://") {
                        let client = UdpTrackerClient::new(Duration::from_secs(3));
                        client.announce(&url, &req).map(|res| res.peers).unwrap_or_default()
                    } else if url.starts_with("http://") || url.starts_with("https://") {
                        let client = HttpTrackerClient::new(Duration::from_secs(3));
                        client.announce(&url, &req).map(|res| res.peers).unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Ok(peers) = res {
                    for p in peers {
                        let addr = SocketAddr::new(IpAddr::V4(p.ip), p.port);
                        if discovered.insert(addr) {
                            let _ = peer_tx.send(addr).await;
                        }
                    }
                }
            }

            /* pause before next announce cycle */
            sleep(Duration::from_secs(30)).await;
        }
    }

    /* manage inbound and outbound peer wire connection tasks with concurrency throttling */
    async fn run_peer_manager(&self, mut peer_rx: mpsc::Receiver<SocketAddr>) {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PEERS));
        let mut peer_counter = 0usize;

        while self.is_running.load(Ordering::SeqCst) {
            tokio::select! {
                Some(addr) = peer_rx.recv() => {
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    peer_counter = peer_counter.wrapping_add(1);
                    let peer_id_idx = peer_counter;
                    let engine = Arc::clone(&Arc::new(self.clone_handles()));

                    tokio::spawn(async move {
                        let _permit = permit;
                        engine.handle_peer(addr, peer_id_idx).await;
                    });
                }
                _ = sleep(Duration::from_millis(100)) => {}
            }
        }
    }

    /* handle individual remote peer wire session lifecycle */
    async fn handle_peer(&self, addr: SocketAddr, peer_idx: usize) {
        /* attempt TCP connection with timeout */
        let stream = match tokio::time::timeout(PEER_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return,
        };

        let local_hs = Handshake::with_extension_support(self.info_hash, self.peer_id);
        let mut remote_stream = stream;

        /* perform initial 68-byte BitTorrent handshake */
        let remote_hs = match tokio::time::timeout(
            Duration::from_secs(4),
            Handshake::exchange(&mut remote_stream, &local_hs, Some(self.info_hash)),
        )
        .await
        {
            Ok(Ok(hs)) => hs,
            _ => return,
        };

        let peer_endpoint = addr.to_string();

        /* register peer in TUI display table */
        {
            let mut app = self.app_state.lock().unwrap();
            app.peers.push(PeerDisplayItem::new(
                peer_endpoint.clone(),
                &remote_hs.peer_id,
                0.0,
                0.0,
                true,
                false,
                0.0,
            ));
        }

        /* register peer in swarm coordinator if active */
        {
            let mut coord_guard = self.coordinator.lock().await;
            if let Some(ref mut coord) = *coord_guard {
                coord.register_peer(peer_idx);
            }
        }

        /* wrap stream in zero-copy peer wire message codec */
        let mut framed = Framed::new(remote_stream, PeerWireCodec::new());

        /* transmit BEP-0010 extended handshake advertising ut_metadata */
        if remote_hs.supports_extensions() {
            let ext_hs = ExtendedHandshake::new();
            let ext_msg = PeerMessage::Extended {
                extended_id: EXTENDED_HANDSHAKE_ID,
                payload: Bytes::from(ext_hs.encode()),
            };
            let _ = framed.send(ext_msg).await;
        }

        /* send interested flag */
        let _ = framed.send(PeerMessage::Interested).await;

        let mut peer_downloaded_bytes = 0u64;
        let mut last_speed_calc = Instant::now();
        let mut peer_bitfield: Option<Bytes> = None;
        let mut is_peer_unchoked = false;
        let mut is_peer_registered = false;

        /* run peer message processing loop */
        while self.is_running.load(Ordering::SeqCst) {
            tokio::select! {
                msg_res = tokio::time::timeout(PEER_READ_TIMEOUT, framed.next()) => {
                    let msg = match msg_res {
                        Ok(Some(Ok(m))) => m,
                        _ => break,
                    };

                    match msg {
                        PeerMessage::Choke => {
                            is_peer_unchoked = false;
                            self.update_peer_choke(&peer_endpoint, true);
                        }
                        PeerMessage::Unchoke => {
                            is_peer_unchoked = true;
                            self.update_peer_choke(&peer_endpoint, false);

                            /* ensure peer registration and bitfield ingestion into coordinator */
                            {
                                let mut coord_guard = self.coordinator.lock().await;
                                if let Some(ref mut coord) = *coord_guard && !is_peer_registered {
                                    coord.register_peer(peer_idx);
                                    if let Some(ref bf) = peer_bitfield {
                                        coord.update_peer_bitfield(peer_idx, bf);
                                    }
                                    is_peer_registered = true;
                                }
                            }

                            self.request_blocks_from_peer(&mut framed, peer_idx).await;
                        }
                        PeerMessage::Interested => {
                            self.update_peer_interest(&peer_endpoint, true);
                        }
                        PeerMessage::NotInterested => {
                            self.update_peer_interest(&peer_endpoint, false);
                        }
                        PeerMessage::Have { piece_index } => {
                            let mut coord_guard = self.coordinator.lock().await;
                            if let Some(ref mut coord) = *coord_guard {
                                if !is_peer_registered {
                                    coord.register_peer(peer_idx);
                                    if let Some(ref bf) = peer_bitfield {
                                        coord.update_peer_bitfield(peer_idx, bf);
                                    }
                                    is_peer_registered = true;
                                }
                                coord.update_peer_have(peer_idx, piece_index);
                            }
                        }
                        PeerMessage::Bitfield { bitfield } => {
                            peer_bitfield = Some(bitfield.clone());
                            let mut coord_guard = self.coordinator.lock().await;
                            if let Some(ref mut coord) = *coord_guard {
                                if !is_peer_registered {
                                    coord.register_peer(peer_idx);
                                    is_peer_registered = true;
                                }
                                coord.update_peer_bitfield(peer_idx, &bitfield);
                            }
                        }
                        PeerMessage::Extended {
                            extended_id,
                            payload,
                        } => {
                            if extended_id == EXTENDED_HANDSHAKE_ID {
                                /* decode BEP-0010 extended handshake */
                                if let Ok(peer_ext) = ExtendedHandshake::decode(&payload) {
                                    let remote_ut_id = peer_ext.ut_metadata_id();

                                    /* initiate BEP-0009 metadata request if torrent metadata is unresolved */
                                    if let Some(meta_size) = peer_ext.metadata_size {
                                        self.initiate_metadata_request(&mut framed, remote_ut_id, meta_size)
                                            .await;
                                    }
                                }
                            } else if extended_id == 1
                                && let Ok(UtMetadataMessage::Data {
                                    piece,
                                    total_size,
                                    data,
                                }) = UtMetadataMessage::decode(&payload)
                            {
                                self.handle_metadata_piece_data(piece, total_size, data).await;
                            }
                        }
                        PeerMessage::Piece {
                            index,
                            begin,
                            block,
                        } => {
                            let block_len = block.len() as u64;
                            peer_downloaded_bytes += block_len;
                            self.total_downloaded_bytes
                                .fetch_add(block_len, Ordering::Relaxed);

                            /* calculate instantaneous peer download speed */
                            let elapsed = last_speed_calc.elapsed().as_secs_f64();
                            if elapsed >= 1.0 {
                                let speed_kib = (peer_downloaded_bytes as f64 / 1024.0) / elapsed;
                                self.update_peer_speed(&peer_endpoint, speed_kib);
                                peer_downloaded_bytes = 0;
                                last_speed_calc = Instant::now();
                            }

                            /* pass block to coordinator for piece assembly and endgame cancellations */
                            let (cancels, assembled_piece) = {
                                let mut coord_guard = self.coordinator.lock().await;
                                if let Some(ref mut coord) = *coord_guard {
                                    coord.on_block_received(peer_idx, index, begin, block)
                                } else {
                                    (Vec::new(), None)
                                }
                            };

                            /* dispatch cancellations to redundant peers if in endgame mode */
                            for cancel in cancels {
                                let cancel_msg = PeerMessage::Cancel {
                                    index: cancel.piece_index,
                                    begin: cancel.begin,
                                    length: cancel.length,
                                };
                                let _ = framed.send(cancel_msg).await;
                            }

                            /* verify completed piece cryptographic SHA-1 integrity */
                            if let Some(piece) = assembled_piece {
                                self.verify_and_commit_piece(piece).await;
                            }

                            /* replenish sliding window pipeline */
                            self.request_blocks_from_peer(&mut framed, peer_idx).await;
                        }
                        _ => {}
                    }
                }
                _ = sleep(Duration::from_millis(500)) => {
                    if is_peer_unchoked {
                        let should_request = {
                            let mut coord_guard = self.coordinator.lock().await;
                            if let Some(ref mut coord) = *coord_guard {
                                if !is_peer_registered {
                                    coord.register_peer(peer_idx);
                                    if let Some(ref bf) = peer_bitfield {
                                        coord.update_peer_bitfield(peer_idx, bf);
                                    }
                                    is_peer_registered = true;
                                }
                                true
                            } else {
                                false
                            }
                        };

                        if should_request {
                            self.request_blocks_from_peer(&mut framed, peer_idx).await;
                        }
                    }
                }
            }
        }

        /* cleanup peer from active coordinator and UI lists upon disconnection */
        {
            let mut coord_guard = self.coordinator.lock().await;
            if let Some(ref mut coord) = *coord_guard {
                coord.unregister_peer(peer_idx);
            }
        }

        {
            let mut app = self.app_state.lock().unwrap();
            app.peers.retain(|p| p.endpoint != peer_endpoint);
        }
    }

    /* initiate BEP-0009 ut_metadata download for unresolved magnet link */
    async fn initiate_metadata_request<S>(
        &self,
        framed: &mut Framed<S, PeerWireCodec>,
        remote_ut_metadata_id: Option<u8>,
        metadata_size: u32,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let ut_id = match remote_ut_metadata_id {
            Some(id) => id,
            None => return,
        };

        let mut reassembler_guard = self.metadata_reassembler.lock().await;
        if reassembler_guard.is_none() {
            *reassembler_guard = Some(MetadataReassembler::new(metadata_size, self.info_hash));
        }

        /* request piece 0 */
        let req = UtMetadataMessage::Request { piece: 0 };
        let msg = PeerMessage::Extended {
            extended_id: ut_id,
            payload: Bytes::from(req.encode()),
        };
        let _ = framed.send(msg).await;
    }

    /* handle incoming BEP-0009 ut_metadata piece chunk */
    async fn handle_metadata_piece_data(&self, piece: u32, total_size: u32, data: Bytes) {
        let mut reassembler_guard = self.metadata_reassembler.lock().await;
        let is_complete = if let Some(ref mut reassembler) = *reassembler_guard {
            reassembler
                .on_piece_data(piece, total_size, data)
                .unwrap_or(false)
        } else {
            false
        };

        if is_complete
            && let Some(ref reassembler) = *reassembler_guard
            && let Ok(full_metadata) = reassembler.assemble_and_verify()
        {
            let primary_trk = self.trackers.first().map(|s| s.as_str()).unwrap_or("");
            if let Ok(metainfo) = reassembler.to_torrent_metainfo(&full_metadata, primary_trk) {
                self.activate_resolved_torrent(&metainfo).await;
            }
        }
    }

    /* transition engine state from metadata resolution to active piece downloading */
    async fn activate_resolved_torrent(&self, metainfo: &Metainfo<'_>) {
        let piece_count = metainfo.piece_count();
        let piece_length = metainfo.piece_length;
        let total_length = metainfo.total_length();

        let name = match &metainfo.file_tree {
            FileTree::SingleFile { name, .. } => (*name).to_string(),
            FileTree::MultiFile { directory_name, .. } => (*directory_name).to_string(),
        };

        /* extract SHA-1 hashes for all pieces */
        let mut expected_hashes = Vec::with_capacity(piece_count);
        for i in 0..piece_count {
            if let Some(hash) = metainfo.piece_hash(i) {
                expected_hashes.push(*hash);
            }
        }

        /* initialize global coordinator */
        let coord = SwarmCoordinator::new(piece_count, piece_length as u32, total_length);
        {
            let mut coord_guard = self.coordinator.lock().await;
            *coord_guard = Some(coord);
        }

        {
            let mut hash_guard = self.expected_piece_hashes.lock().await;
            *hash_guard = expected_hashes;
        }

        /* initialize disk manager to memory-map file targets in download directory */
        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().ok();
        if let Some(p) = pool
            && let Ok(dm) = DiskManager::from_metainfo(&self.download_dir, metainfo, p)
        {
            let mut dm_guard = self.disk_manager.lock().await;
            *dm_guard = Some(dm);
        }

        /* update TUI state model with real torrent geometry */
        {
            let mut app = self.app_state.lock().unwrap();
            app.torrent_name = name;
            app.total_pieces = piece_count;
            app.piece_length = piece_length;
            app.total_bytes = total_length;
            app.piece_states = vec![PieceVisualState::Missing; piece_count];
            app.is_magnet_resolving = false;
        }
    }

    /* query coordinator and transmit up to 32 pipelined block requests to remote peer */
    async fn request_blocks_from_peer<S>(
        &self,
        framed: &mut Framed<S, PeerWireCodec>,
        peer_idx: usize,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let requests = {
            let mut coord_guard = self.coordinator.lock().await;
            if let Some(ref mut coord) = *coord_guard {
                coord.next_requests_for_peer(peer_idx, PIPELINE_CAPACITY_32)
            } else {
                Vec::new()
            }
        };

        for req in requests {
            /* mark piece as in-flight in TUI heatmap */
            if let PeerMessage::Request { index, .. } = req {
                let mut app = self.app_state.lock().unwrap();
                if (index as usize) < app.piece_states.len()
                    && app.piece_states[index as usize] != PieceVisualState::Downloaded
                {
                    app.piece_states[index as usize] = PieceVisualState::InFlight;
                }
            }

            if framed.send(req).await.is_err() {
                break;
            }
        }
    }

    /* verify cryptographic SHA-1 hash for reassembled piece, write to disk, and update UI */
    async fn verify_and_commit_piece(&self, piece: crate::peer::session::AssembledPiece) {
        let piece_idx = piece.index as usize;

        let mut dm_guard = self.disk_manager.lock().await;
        if let Some(ref mut dm) = *dm_guard {
            if dm.verify_and_write_piece(piece.index, &piece.data).is_ok() {
                let mut app = self.app_state.lock().unwrap();
                if piece_idx < app.piece_states.len() {
                    app.piece_states[piece_idx] = PieceVisualState::Downloaded;
                }
                let piece_len = app.piece_length;
                app.downloaded_bytes = (app.downloaded_bytes + piece_len).min(app.total_bytes);
            }
        } else {
            let expected_hash = {
                let hashes = self.expected_piece_hashes.lock().await;
                hashes.get(piece_idx).copied()
            };

            if let Some(expected) = expected_hash {
                let calculated = Sha1::digest(&piece.data);
                if calculated == expected {
                    let mut app = self.app_state.lock().unwrap();
                    if piece_idx < app.piece_states.len() {
                        app.piece_states[piece_idx] = PieceVisualState::Downloaded;
                    }
                    let piece_len = app.piece_length;
                    app.downloaded_bytes = (app.downloaded_bytes + piece_len).min(app.total_bytes);
                }
            }
        }
    }

    /* record instantaneous throughput telemetry into TUI sparklines */
    async fn run_throughput_sampler(&self) {
        let mut last_sample_time = Instant::now();
        let mut prev_down = self.total_downloaded_bytes.load(Ordering::Relaxed);
        let mut prev_up = self.total_uploaded_bytes.load(Ordering::Relaxed);

        while self.is_running.load(Ordering::SeqCst) {
            sleep(Duration::from_millis(500)).await;

            let now = Instant::now();
            let elapsed_secs = (now - last_sample_time).as_secs_f64();
            if elapsed_secs <= 0.0 {
                continue;
            }

            let cur_down = self.total_downloaded_bytes.load(Ordering::Relaxed);
            let cur_up = self.total_uploaded_bytes.load(Ordering::Relaxed);

            let down_diff = cur_down.saturating_sub(prev_down);
            let up_diff = cur_up.saturating_sub(prev_up);

            let down_kib = (down_diff as f64 / 1024.0) / elapsed_secs;
            let up_kib = (up_diff as f64 / 1024.0) / elapsed_secs;

            {
                let mut app = self.app_state.lock().unwrap();
                app.record_throughput_sample(down_kib, up_kib);

                /* update endgame mode flag from coordinator */
                if let Ok(coord_guard) = self.coordinator.try_lock()
                    && let Some(ref coord) = *coord_guard
                {
                    app.is_endgame = coord.is_endgame;
                }
            }

            prev_down = cur_down;
            prev_up = cur_up;
            last_sample_time = now;
        }
    }

    /* helper updating peer choke flag in UI table */
    fn update_peer_choke(&self, endpoint: &str, is_choked: bool) {
        let mut app = self.app_state.lock().unwrap();
        if let Some(peer) = app.peers.iter_mut().find(|p| p.endpoint == endpoint) {
            peer.is_choked = is_choked;
        }
    }

    /* helper updating peer interested flag in UI table */
    fn update_peer_interest(&self, endpoint: &str, is_interested: bool) {
        let mut app = self.app_state.lock().unwrap();
        if let Some(peer) = app.peers.iter_mut().find(|p| p.endpoint == endpoint) {
            peer.is_interested = is_interested;
        }
    }

    /* helper updating peer throughput in UI table */
    fn update_peer_speed(&self, endpoint: &str, speed_kib: f64) {
        let mut app = self.app_state.lock().unwrap();
        if let Some(peer) = app.peers.iter_mut().find(|p| p.endpoint == endpoint) {
            peer.download_speed_kib = speed_kib;
        }
    }

    /* clone Arc handles for worker task detachment */
    fn clone_handles(&self) -> Self {
        Self {
            info_hash: self.info_hash,
            peer_id: self.peer_id,
            trackers: self.trackers.clone(),
            download_dir: self.download_dir.clone(),
            app_state: Arc::clone(&self.app_state),
            coordinator: Arc::clone(&self.coordinator),
            disk_manager: Arc::clone(&self.disk_manager),
            expected_piece_hashes: Arc::clone(&self.expected_piece_hashes),
            metadata_reassembler: Arc::clone(&self.metadata_reassembler),
            total_downloaded_bytes: Arc::clone(&self.total_downloaded_bytes),
            total_uploaded_bytes: Arc::clone(&self.total_uploaded_bytes),
            is_running: Arc::clone(&self.is_running),
        }
    }
}
