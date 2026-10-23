/* manage BEP-0010 extension protocol primitives, extended handshake, and message multiplexing */

use crate::bencode::{parse, BencodeError, BencodeValue};
use std::collections::BTreeMap;
use std::fmt;

pub mod metadata;

/* extended handshake message identifier per BEP-0010 specification */
pub const EXTENDED_HANDSHAKE_ID: u8 = 0;

/* canonical extension name for BEP-0009 metadata exchange */
pub const EXTENSION_NAME_UT_METADATA: &str = "ut_metadata";

/* errors occurring during BEP-0010 extension protocol processing */
#[derive(Debug)]
pub enum ExtensionError {
    /* wrapped bencode decoding error */
    Bencode(BencodeError),
    /* extended handshake payload was malformed or missing required keys */
    InvalidHandshake(&'static str),
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bencode(err) => write!(f, "bencode decoding failure: {err}"),
            Self::InvalidHandshake(msg) => write!(f, "invalid extended handshake: {msg}"),
        }
    }
}

impl std::error::Error for ExtensionError {}

impl From<BencodeError> for ExtensionError {
    fn from(err: BencodeError) -> Self {
        Self::Bencode(err)
    }
}

/* structure BEP-0010 extended handshake dictionary exchanging dynamic extension IDs and swarm metrics */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedHandshake {
    /* mapping of extension name strings to remote peer's assigned extended message IDs */
    pub extensions: BTreeMap<String, u8>,
    /* total byte length of torrent info dictionary advertised by peer */
    pub metadata_size: Option<u32>,
    /* human-readable client version identification string */
    pub client_version: Option<String>,
    /* maximum outstanding block request queue limit */
    pub reqq: Option<u32>,
}

impl Default for ExtendedHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedHandshake {
    /* construct local extended handshake advertising ut_metadata extension support */
    pub fn new() -> Self {
        let mut extensions = BTreeMap::new();
        /* assign local extended message ID 1 to ut_metadata */
        extensions.insert(EXTENSION_NAME_UT_METADATA.to_string(), 1);

        Self {
            extensions,
            metadata_size: None,
            client_version: Some("bolt 0.1.0".to_string()),
            reqq: Some(255),
        }
    }

    /* attach known metadata size when seeding or advertising metadata */
    pub fn with_metadata_size(mut self, size: u32) -> Self {
        self.metadata_size = Some(size);
        self
    }

    /* lookup the remote peer's assigned message ID for ut_metadata extension */
    pub fn ut_metadata_id(&self) -> Option<u8> {
        self.extensions.get(EXTENSION_NAME_UT_METADATA).copied()
    }

    /* encode extended handshake as canonical bencoded dictionary */
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(b'd');

        /* encode extension mapping dictionary 'm' in sorted key order */
        buf.extend_from_slice(b"1:md");
        for (name, &id) in &self.extensions {
            use std::io::Write;
            let _ = write!(&mut buf, "{}:{}i{}", name.len(), name, id);
            buf.push(b'e');
        }
        buf.push(b'e'); /* close 'm' dict */

        /* encode optional metadata_size */
        if let Some(size) = self.metadata_size {
            use std::io::Write;
            let _ = write!(&mut buf, "13:metadata_sizei{}e", size);
        }

        /* encode optional reqq */
        if let Some(reqq) = self.reqq {
            use std::io::Write;
            let _ = write!(&mut buf, "4:reqqi{}e", reqq);
        }

        /* encode optional client version string 'v' */
        if let Some(ref v) = self.client_version {
            use std::io::Write;
            let _ = write!(&mut buf, "1:v{}:{}", v.len(), v);
        }

        buf.push(b'e'); /* close root dict */
        buf
    }

    /* decode extended handshake from bencoded payload */
    pub fn decode(payload: &[u8]) -> Result<Self, ExtensionError> {
        let root = parse(payload)?;

        /* parse 'm' extension map dictionary */
        let mut extensions = BTreeMap::new();
        if let Some(m_val) = root.dict_get_by_str("m")
            && let Some(entries) = m_val.as_dict()
        {
            for entry in entries {
                if let Ok(name) = std::str::from_utf8(entry.key)
                    && let Some(id) = entry.value.as_i64()
                {
                    extensions.insert(name.to_string(), id as u8);
                }
            }
        }

        /* extract optional metadata_size */
        let metadata_size = root
            .dict_get_by_str("metadata_size")
            .and_then(BencodeValue::as_i64)
            .map(|s| s as u32);

        /* extract optional client version string */
        let client_version = root
            .dict_get_by_str("v")
            .and_then(BencodeValue::as_str)
            .map(|s| s.to_string());

        /* extract optional reqq */
        let reqq = root
            .dict_get_by_str("reqq")
            .and_then(BencodeValue::as_i64)
            .map(|r| r as u32);

        Ok(Self {
            extensions,
            metadata_size,
            client_version,
            reqq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_handshake_roundtrip() {
        let handshake = ExtendedHandshake::new()
            .with_metadata_size(65536);

        let encoded = handshake.encode();
        let decoded = ExtendedHandshake::decode(&encoded).expect("handshake decoding failed");

        assert_eq!(decoded.ut_metadata_id(), Some(1));
        assert_eq!(decoded.metadata_size, Some(65536));
        assert_eq!(decoded.client_version, Some("bolt 0.1.0".to_string()));
        assert_eq!(decoded.reqq, Some(255));
    }
}
