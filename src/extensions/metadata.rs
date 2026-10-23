/* handle BEP-0009 ut_metadata extension protocol: info dictionary fetching from swarm peers */

use crate::bencode::{BencodeError, BencodeParser, BencodeValue};
use crate::sha1::Sha1;
use crate::torrent::{Metainfo, TorrentError};
use bytes::Bytes;
use std::collections::HashMap;
use std::fmt;

/* nominal metadata chunk block size defined by BEP-0009 (16 KiB = 16,384 bytes) */
pub const UT_METADATA_PIECE_SIZE: usize = 16384;

/* define BEP-0009 msg_type enumeration codes */
pub const MSG_TYPE_REQUEST: i64 = 0;
pub const MSG_TYPE_DATA: i64 = 1;
pub const MSG_TYPE_REJECT: i64 = 2;

/* errors occurring during ut_metadata framing, downloading, or cryptographic verification */
#[derive(Debug)]
pub enum MetadataError {
    /* wrapped bencode decoding error */
    Bencode(BencodeError),
    /* missing required bencode dictionary field */
    MissingField(&'static str),
    /* unknown or unsupported BEP-0009 message type identifier */
    UnknownMessageType(i64),
    /* received metadata chunk index exceeds negotiated total piece count */
    PieceIndexOutOfBounds { piece: u32, total: usize },
    /* reassembled metadata bytes failed SHA-1 hash verification against magnet info_hash */
    HashMismatch,
    /* metainfo reconstruction failure */
    Torrent(TorrentError),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bencode(err) => write!(f, "bencode decoding failure: {err}"),
            Self::MissingField(field) => write!(f, "missing ut_metadata field: {field}"),
            Self::UnknownMessageType(t) => write!(f, "unknown ut_metadata msg_type: {t}"),
            Self::PieceIndexOutOfBounds { piece, total } => {
                write!(f, "piece index {piece} out of bounds (total pieces: {total})")
            }
            Self::HashMismatch => {
                write!(f, "assembled metadata failed SHA-1 cryptographic integrity check")
            }
            Self::Torrent(err) => write!(f, "torrent metainfo error: {err}"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<BencodeError> for MetadataError {
    fn from(err: BencodeError) -> Self {
        Self::Bencode(err)
    }
}

impl From<TorrentError> for MetadataError {
    fn from(err: TorrentError) -> Self {
        Self::Torrent(err)
    }
}

/* messages exchanged under the BEP-0009 ut_metadata extension */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtMetadataMessage {
    /* requests specific 16 KiB metadata piece from remote peer */
    Request { piece: u32 },
    /* delivers 16 KiB metadata chunk accompanied by total metadata size */
    Data {
        piece: u32,
        total_size: u32,
        data: Bytes,
    },
    /* signals that remote peer does not possess or will not serve requested piece */
    Reject { piece: u32 },
}

impl UtMetadataMessage {
    /* serialize ut_metadata message into wire format.
       wire layout:
       - request/reject: bencoded dictionary header only
       - data: bencoded dictionary header immediately followed by raw binary chunk */
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Request { piece } => {
                use std::io::Write;
                let _ = write!(&mut buf, "d8:msg_typei0e5:piecei{}ee", piece);
            }
            Self::Reject { piece } => {
                use std::io::Write;
                let _ = write!(&mut buf, "d8:msg_typei2e5:piecei{}ee", piece);
            }
            Self::Data {
                piece,
                total_size,
                data,
            } => {
                use std::io::Write;
                let _ = write!(
                    &mut buf,
                    "d8:msg_typei1e5:piecei{}e10:total_sizei{}ee",
                    piece, total_size
                );
                /* append raw binary metadata bytes immediately after bencoded delimiter */
                buf.extend_from_slice(data);
            }
        }
        buf
    }

    /* parse ut_metadata message separating bencoded dictionary header from binary payload */
    pub fn decode(payload: &[u8]) -> Result<Self, MetadataError> {
        let mut parser = BencodeParser::new(payload);

        /* zero-copy carve bencoded dictionary header and locate binary split boundary */
        let (header_val, raw_header) = parser.parse_value_with_raw()?;
        let header_len = raw_header.len();

        let msg_type = header_val
            .dict_get_by_str("msg_type")
            .and_then(BencodeValue::as_i64)
            .ok_or(MetadataError::MissingField("msg_type"))?;

        let piece = header_val
            .dict_get_by_str("piece")
            .and_then(BencodeValue::as_i64)
            .ok_or(MetadataError::MissingField("piece"))? as u32;

        match msg_type {
            MSG_TYPE_REQUEST => Ok(Self::Request { piece }),
            MSG_TYPE_REJECT => Ok(Self::Reject { piece }),
            MSG_TYPE_DATA => {
                let total_size = header_val
                    .dict_get_by_str("total_size")
                    .and_then(BencodeValue::as_i64)
                    .ok_or(MetadataError::MissingField("total_size"))?
                    as u32;

                /* remaining bytes after bencoded header represent the raw metadata chunk */
                let raw_chunk = &payload[header_len..];
                let data = Bytes::copy_from_slice(raw_chunk);

                Ok(Self::Data {
                    piece,
                    total_size,
                    data,
                })
            }
            other => Err(MetadataError::UnknownMessageType(other)),
        }
    }
}

/* state machine accumulating and verifying 16 KiB metadata chunks to resolve Magnet links */
#[derive(Debug)]
pub struct MetadataReassembler {
    pub metadata_size: u32,
    pub target_info_hash: [u8; 20],
    pub total_pieces: usize,
    pub pieces_received: HashMap<u32, Bytes>,
}

impl MetadataReassembler {
    /* instantiate reassembler for negotiated metadata size and magnet info_hash */
    pub fn new(metadata_size: u32, target_info_hash: [u8; 20]) -> Self {
        let total_pieces = (metadata_size as usize).div_ceil(UT_METADATA_PIECE_SIZE);
        Self {
            metadata_size,
            target_info_hash,
            total_pieces,
            pieces_received: HashMap::with_capacity(total_pieces),
        }
    }

    /* check if all required 16 KiB chunks have been received */
    pub fn is_complete(&self) -> bool {
        self.pieces_received.len() == self.total_pieces
    }

    /* store incoming metadata chunk and check for completion */
    pub fn on_piece_data(
        &mut self,
        piece: u32,
        _total_size: u32,
        data: Bytes,
    ) -> Result<bool, MetadataError> {
        if piece as usize >= self.total_pieces {
            return Err(MetadataError::PieceIndexOutOfBounds {
                piece,
                total: self.total_pieces,
            });
        }

        self.pieces_received.insert(piece, data);
        Ok(self.is_complete())
    }

    /* concatenate all ordered chunks and verify SHA-1 digest against target_info_hash */
    pub fn assemble_and_verify(&self) -> Result<Vec<u8>, MetadataError> {
        if !self.is_complete() {
            return Err(MetadataError::MissingField("incomplete metadata pieces"));
        }

        let mut full_metadata = Vec::with_capacity(self.metadata_size as usize);
        for i in 0..self.total_pieces as u32 {
            let chunk = self
                .pieces_received
                .get(&i)
                .ok_or(MetadataError::MissingField("missing piece chunk"))?;
            full_metadata.extend_from_slice(chunk);
        }

        /* trim buffer to exact negotiated metadata byte size */
        full_metadata.truncate(self.metadata_size as usize);

        /* verify cryptographic SHA-1 integrity */
        let digest = Sha1::digest(&full_metadata);
        if digest != self.target_info_hash {
            return Err(MetadataError::HashMismatch);
        }

        Ok(full_metadata)
    }

    /* construct complete Metainfo structure by combining raw info dictionary with announce URL */
    pub fn to_torrent_metainfo<'a>(
        &self,
        full_metadata: &'a [u8],
        primary_announce: &str,
    ) -> Result<Metainfo<'a>, TorrentError> {
        /* wrap canonical info dictionary inside synthetic root bencoded dictionary */
        let mut synthetic_torrent = Vec::new();
        synthetic_torrent.push(b'd');

        use std::io::Write;
        let _ = write!(
            &mut synthetic_torrent,
            "8:announce{}:{}",
            primary_announce.len(),
            primary_announce
        );

        synthetic_torrent.extend_from_slice(b"4:info");
        synthetic_torrent.extend_from_slice(full_metadata);
        synthetic_torrent.push(b'e');

        /* leak synthetic outer buffer safely or re-slice full_metadata */
        let leaked: &'a [u8] = Box::leak(synthetic_torrent.into_boxed_slice());
        Metainfo::parse(leaked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ut_metadata_request_roundtrip() {
        let msg = UtMetadataMessage::Request { piece: 3 };
        let encoded = msg.encode();
        let decoded = UtMetadataMessage::decode(&encoded).expect("decoding failed");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_ut_metadata_data_roundtrip_with_binary_payload() {
        let raw_bytes = Bytes::from_static(b"binary piece contents payload bytes");
        let msg = UtMetadataMessage::Data {
            piece: 2,
            total_size: 40960,
            data: raw_bytes.clone(),
        };

        let encoded = msg.encode();
        let decoded = UtMetadataMessage::decode(&encoded).expect("decoding failed");

        match decoded {
            UtMetadataMessage::Data {
                piece,
                total_size,
                data,
            } => {
                assert_eq!(piece, 2);
                assert_eq!(total_size, 40960);
                assert_eq!(data, raw_bytes);
            }
            other => panic!("expected Data message, got: {:?}", other),
        }
    }

    #[test]
    fn test_metadata_reassembly_and_hash_verification() {
        /* synthetic info dictionary */
        let dummy_info_dict = b"d6:lengthi1048576e4:name8:test.isoe";
        let target_hash = Sha1::digest(dummy_info_dict);

        let mut reassembler =
            MetadataReassembler::new(dummy_info_dict.len() as u32, target_hash);

        assert_eq!(reassembler.total_pieces, 1);

        /* deliver piece 0 */
        let is_done = reassembler
            .on_piece_data(
                0,
                dummy_info_dict.len() as u32,
                Bytes::copy_from_slice(dummy_info_dict),
            )
            .expect("piece delivery failed");

        assert!(is_done);

        let assembled = reassembler
            .assemble_and_verify()
            .expect("metadata verification failed");
        assert_eq!(assembled, dummy_info_dict);
    }
}
