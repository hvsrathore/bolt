/* state container and models driving the ratatui terminal user interface */

use crate::peer::client_info::parse_peer_client;

/* individual peer status record formatted for TUI tabular presentation */
#[derive(Debug, Clone, PartialEq)]
pub struct PeerDisplayItem {
    pub endpoint: String,
    pub client_name: String,
    pub download_speed_kib: f64,
    pub upload_speed_kib: f64,
    pub is_choked: bool,
    pub is_interested: bool,
    pub progress_pct: f64,
}

impl PeerDisplayItem {
    /* construct peer display row with client fingerprint parsing */
    pub fn new(
        endpoint: String,
        peer_id: &[u8; 20],
        download_speed_kib: f64,
        upload_speed_kib: f64,
        is_choked: bool,
        is_interested: bool,
        progress_pct: f64,
    ) -> Self {
        let client_name = parse_peer_client(peer_id);
        Self {
            endpoint,
            client_name,
            download_speed_kib,
            upload_speed_kib,
            is_choked,
            is_interested,
            progress_pct,
        }
    }
}

/* piece status classification for heatmap cell colorization */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceVisualState {
    /* piece is not yet requested and unverified on disk */
    Missing,
    /* piece has low swarm availability (rarity <= 2) */
    Rare,
    /* piece blocks currently in flight across peer wire sessions */
    InFlight,
    /* piece completely assembled, SHA-1 verified, and flushed to disk */
    Downloaded,
}

/* state model accumulating torrent metrics, throughput buffers, and peer telemetry */
#[derive(Debug, Clone)]
pub struct AppState {
    pub torrent_name: String,
    pub info_hash_hex: String,
    pub total_pieces: usize,
    pub piece_length: u64,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub is_magnet_resolving: bool,
    pub is_endgame: bool,
    pub piece_states: Vec<PieceVisualState>,
    pub peers: Vec<PeerDisplayItem>,
    pub download_sparkline: Vec<u64>,
    pub upload_sparkline: Vec<u64>,
    pub current_down_kib: f64,
    pub current_up_kib: f64,
}

impl AppState {
    /* construct initial demo state for testing and active runtime */
    pub fn new(
        torrent_name: String,
        info_hash_hex: String,
        total_pieces: usize,
        piece_length: u64,
        total_bytes: u64,
    ) -> Self {
        Self {
            torrent_name,
            info_hash_hex,
            total_pieces,
            piece_length,
            total_bytes,
            downloaded_bytes: 0,
            is_magnet_resolving: false,
            is_endgame: false,
            piece_states: vec![PieceVisualState::Missing; total_pieces],
            peers: Vec::new(),
            download_sparkline: vec![0; 60],
            upload_sparkline: vec![0; 60],
            current_down_kib: 0.0,
            current_up_kib: 0.0,
        }
    }

    /* calculate download progress percentage (0.0 to 100.0) */
    pub fn download_progress(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            (self.downloaded_bytes as f64 / self.total_bytes as f64) * 100.0
        }
    }

    /* append instantaneous throughput sample into sliding sparkline buffer */
    pub fn record_throughput_sample(&mut self, down_kib: f64, up_kib: f64) {
        self.current_down_kib = down_kib;
        self.current_up_kib = up_kib;

        /* maintain fixed 60-sample window */
        if self.download_sparkline.len() >= 60 {
            self.download_sparkline.remove(0);
        }
        self.download_sparkline.push(down_kib as u64);

        if self.upload_sparkline.len() >= 60 {
            self.upload_sparkline.remove(0);
        }
        self.upload_sparkline.push(up_kib as u64);
    }
}
