/* bolt - BitTorrent metainfo, zero-copy Bencode, tracker, peer wire, extensions, disk, and TUI engine */

pub mod bencode;
pub mod coordinator;
pub mod disk;
pub mod extensions;
pub mod magnet;
pub mod peer;
pub mod sha1;
pub mod torrent;
pub mod tracker;
pub mod ui;

/* re-export primary public abstractions for convenient client consumption */
pub use bencode::{
    parse as parse_bencode, parse_strict as parse_bencode_strict, BencodeError, BencodeValue,
    DictEntry,
};
pub use coordinator::{BlockKey, PeerCancelDirective, SwarmCoordinator};
pub use disk::{DiskError, DiskManager, MappedFile};
pub use extensions::{
    metadata::{MetadataError, MetadataReassembler, UtMetadataMessage},
    ExtendedHandshake, ExtensionError, EXTENDED_HANDSHAKE_ID, EXTENSION_NAME_UT_METADATA,
};
pub use magnet::{MagnetError, MagnetLink};
pub use peer::{
    client_info::parse_peer_client,
    codec::{PeerMessage, PeerWireCodec},
    session::{
        spawn_peer_session, AssembledPiece, BlockRequest, PeerSession, PeerSessionHandle,
        PieceReassembly, SessionCommand, SessionEvent, BLOCK_SIZE_16KIB, PIPELINE_CAPACITY_32,
    },
    Handshake, PeerWireError,
};
pub use sha1::{Sha1, SHA1_DIGEST_LENGTH};
pub use torrent::{FileInfo, FileTree, Metainfo, TorrentError};
pub use tracker::{
    http::HttpTrackerClient,
    parse_compact_peers_ipv4,
    udp::UdpTrackerClient,
    AnnounceEvent, AnnounceRequest, AnnounceResponse, Peer, TrackerError,
};
pub use ui::{
    app::{AppState, PeerDisplayItem, PieceVisualState},
    render_dashboard,
};
