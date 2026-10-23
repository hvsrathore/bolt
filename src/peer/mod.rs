/* manage BitTorrent peer wire protocol primitives, handshake negotiation, and wire errors */

use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod client_info;
pub mod codec;
pub mod session;

pub use client_info::parse_peer_client;

/* length of protocol identifier string 'BitTorrent protocol' */
pub const PROTOCOL_STRING_LENGTH: usize = 19;
pub const PROTOCOL_STRING: &[u8; PROTOCOL_STRING_LENGTH] = b"BitTorrent protocol";

/* length of the complete wire handshake in bytes (1 + 19 + 8 + 20 + 20 = 68) */
pub const HANDSHAKE_LENGTH: usize = 68;

/* default 8-byte reserved extension flags (all zeros for baseline BEP-0003) */
pub const RESERVED_DEFAULT: [u8; 8] = [0u8; 8];

/* flag BEP-0010 extension protocol bit mask (bit 20 from right / byte index 5, mask 0x10) */
pub const RESERVED_EXTENSION_PROTOCOL_BYTE_INDEX: usize = 5;
pub const RESERVED_EXTENSION_PROTOCOL_MASK: u8 = 0x10;

/* errors encountered during peer wire framing, handshakes, and session operations */
#[derive(Debug)]
pub enum PeerWireError {
    /* underlying asynchronous I/O failure */
    Io(std::io::Error),
    /* handshake length byte differed from standard 19 */
    InvalidProtocolStringLength(u8),
    /* handshake protocol string differed from 'BitTorrent protocol' */
    InvalidProtocolString,
    /* peer info_hash did not match expected torrent info_hash */
    InfoHashMismatch {
        expected: [u8; 20],
        received: [u8; 20],
    },
    /* peer sent unknown or unsupported message identifier byte */
    UnknownMessageId(u8),
    /* frame length exceeded maximum permissible buffer limit */
    MessageTooLarge(usize),
    /* payload size does not match required dimensions for message type */
    InvalidPayloadLength {
        expected: usize,
        actual: usize,
    },
    /* piece block was rejected due to index or bounds violation */
    InvalidBlockBounds {
        index: u32,
        begin: u32,
        length: u32,
    },
    /* reassembled piece failed SHA-1 cryptographic digest verification */
    PieceHashMismatch {
        index: u32,
    },
    /* peer connection terminated unexpectedly */
    ConnectionClosed,
}

impl fmt::Display for PeerWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidProtocolStringLength(len) => {
                write!(f, "invalid protocol string length {len}, expected 19")
            }
            Self::InvalidProtocolString => write!(f, "protocol string is not 'BitTorrent protocol'"),
            Self::InfoHashMismatch { .. } => write!(f, "peer info_hash mismatch"),
            Self::UnknownMessageId(id) => write!(f, "unknown message ID: 0x{id:02x}"),
            Self::MessageTooLarge(len) => write!(f, "message length {len} exceeds safety limit"),
            Self::InvalidPayloadLength { expected, actual } => {
                write!(f, "invalid payload length: expected {expected}, got {actual}")
            }
            Self::InvalidBlockBounds { index, begin, length } => {
                write!(f, "invalid block bounds for piece {index}: begin {begin}, len {length}")
            }
            Self::PieceHashMismatch { index } => {
                write!(f, "piece {index} failed SHA-1 integrity verification")
            }
            Self::ConnectionClosed => write!(f, "peer connection closed"),
        }
    }
}

impl std::error::Error for PeerWireError {}

impl From<std::io::Error> for PeerWireError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/* initial connection handshake exchanging info_hash, peer_id, and extension capabilities.
   wire format (68 bytes total):
   - 0..1:   pstrlen (u8 = 19)
   - 1..20:  pstr (19 bytes = "BitTorrent protocol")
   - 20..28: reserved (8 bytes, extension flags)
   - 28..48: info_hash (20 bytes, torrent SHA-1 digest)
   - 48..68: peer_id (20 bytes, client unique ID) */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    /* construct baseline handshake with clean reserved bytes */
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self {
            reserved: RESERVED_DEFAULT,
            info_hash,
            peer_id,
        }
    }

    /* construct handshake with BEP-0010 extension protocol support enabled */
    pub fn with_extension_support(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        let mut reserved = RESERVED_DEFAULT;
        reserved[RESERVED_EXTENSION_PROTOCOL_BYTE_INDEX] |= RESERVED_EXTENSION_PROTOCOL_MASK;
        Self {
            reserved,
            info_hash,
            peer_id,
        }
    }

    /* check if remote peer advertises BEP-0010 extension protocol support */
    pub fn supports_extensions(&self) -> bool {
        (self.reserved[RESERVED_EXTENSION_PROTOCOL_BYTE_INDEX] & RESERVED_EXTENSION_PROTOCOL_MASK) != 0
    }

    /* serialize handshake into contiguous 68-byte wire frame */
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_LENGTH] {
        let mut bytes = [0u8; HANDSHAKE_LENGTH];
        bytes[0] = PROTOCOL_STRING_LENGTH as u8;
        bytes[1..20].copy_from_slice(PROTOCOL_STRING);
        bytes[20..28].copy_from_slice(&self.reserved);
        bytes[28..48].copy_from_slice(&self.info_hash);
        bytes[48..68].copy_from_slice(&self.peer_id);
        bytes
    }

    /* deserialize handshake from raw 68-byte slice, validating protocol identifier */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerWireError> {
        if bytes.len() < HANDSHAKE_LENGTH {
            return Err(PeerWireError::InvalidPayloadLength {
                expected: HANDSHAKE_LENGTH,
                actual: bytes.len(),
            });
        }

        let pstrlen = bytes[0];
        if pstrlen != (PROTOCOL_STRING_LENGTH as u8) {
            return Err(PeerWireError::InvalidProtocolStringLength(pstrlen));
        }

        if &bytes[1..20] != PROTOCOL_STRING {
            return Err(PeerWireError::InvalidProtocolString);
        }

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&bytes[20..28]);

        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&bytes[28..48]);

        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&bytes[48..68]);

        Ok(Self {
            reserved,
            info_hash,
            peer_id,
        })
    }

    /* perform asynchronous bidirectional handshake exchange over generic async stream */
    pub async fn exchange<S>(
        stream: &mut S,
        local_handshake: &Handshake,
        expected_info_hash: Option<[u8; 20]>,
    ) -> Result<Handshake, PeerWireError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        /* transmit local 68-byte handshake */
        let out_bytes = local_handshake.to_bytes();
        stream.write_all(&out_bytes).await?;
        stream.flush().await?;

        /* read remote 68-byte response handshake */
        let mut in_bytes = [0u8; HANDSHAKE_LENGTH];
        stream.read_exact(&mut in_bytes).await?;
        let remote_handshake = Handshake::from_bytes(&in_bytes)?;

        /* optionally verify that remote peer has matching info_hash */
        if let Some(expected) = expected_info_hash
            && remote_handshake.info_hash != expected
        {
            return Err(PeerWireError::InfoHashMismatch {
                expected,
                received: remote_handshake.info_hash,
            });
        }

        Ok(remote_handshake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let info_hash = [0x55u8; 20];
        let peer_id = [0x77u8; 20];
        let handshake = Handshake::with_extension_support(info_hash, peer_id);

        let bytes = handshake.to_bytes();
        assert_eq!(bytes.len(), 68);
        assert_eq!(bytes[0], 19);
        assert_eq!(&bytes[1..20], b"BitTorrent protocol");

        let parsed = Handshake::from_bytes(&bytes).expect("handshake parsing failed");
        assert_eq!(parsed.info_hash, info_hash);
        assert_eq!(parsed.peer_id, peer_id);
        assert!(parsed.supports_extensions());
    }

    #[test]
    fn test_handshake_invalid_protocol_string() {
        let mut bytes = [0u8; 68];
        bytes[0] = 19;
        bytes[1..20].copy_from_slice(b"FakeTorrentProtocol");

        assert!(matches!(
            Handshake::from_bytes(&bytes),
            Err(PeerWireError::InvalidProtocolString)
        ));
    }
}
