/* parse Magnet URI supporting hex and base32 info_hash, display name, and trackers */

use std::fmt;

/* errors encountered while deserializing magnet links */
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MagnetError {
    /* specified URI does not begin with 'magnet:?' scheme */
    MissingMagnetScheme,
    /* exact topic xt parameter missing or lacks 'urn:btih:' prefix */
    MissingExactTopic,
    /* info_hash string is neither 40-char hex nor 32-char base32 */
    InvalidInfoHashLength(usize),
    /* info_hash string contains invalid non-hex or non-base32 character */
    InvalidInfoHashCharacter(char),
}

impl fmt::Display for MagnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMagnetScheme => write!(f, "magnet URI must start with 'magnet:?'"),
            Self::MissingExactTopic => write!(f, "missing or invalid 'xt=urn:btih:' topic parameter"),
            Self::InvalidInfoHashLength(len) => {
                write!(f, "invalid info_hash length {len}: expected 40 hex or 32 base32 characters")
            }
            Self::InvalidInfoHashCharacter(c) => write!(f, "invalid character '{c}' in info_hash"),
        }
    }
}

impl std::error::Error for MagnetError {}

/* parsed Magnet link representation containing cryptographic info_hash and swarm endpoints */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    /* 20-byte SHA-1 digest identifying torrent metadata */
    pub info_hash: [u8; 20],
    /* optional human-readable display name extracted from dn parameter */
    pub display_name: Option<String>,
    /* collection of tracker URLs specified via tr parameters */
    pub trackers: Vec<String>,
    /* optional file size in bytes extracted from xl parameter */
    pub exact_length: Option<u64>,
}

impl MagnetLink {
    /* parse standard magnet URI string */
    pub fn parse(uri: &str) -> Result<Self, MagnetError> {
        let trimmed = uri.trim();
        let query_string = trimmed
            .strip_prefix("magnet:?")
            .ok_or(MagnetError::MissingMagnetScheme)?;

        let mut info_hash = None;
        let mut display_name = None;
        let mut trackers = Vec::new();
        let mut exact_length = None;

        /* decompose query parameters split on '&' */
        for param in query_string.split('&') {
            if param.is_empty() {
                continue;
            }

            let (key, val) = match param.find('=') {
                Some(idx) => (&param[..idx], &param[idx + 1..]),
                None => (param, ""),
            };

            match key {
                "xt" => {
                    /* exact topic must specify standard BitTorrent info_hash */
                    if let Some(hash_str) = val.strip_prefix("urn:btih:") {
                        info_hash = Some(Self::decode_info_hash(hash_str)?);
                    }
                }
                "dn" => {
                    display_name = Some(Self::percent_decode(val));
                }
                "tr" => {
                    let decoded_tracker = Self::percent_decode(val);
                    if !decoded_tracker.is_empty() {
                        trackers.push(decoded_tracker);
                    }
                }
                "xl" => {
                    if let Ok(len) = val.parse::<u64>() {
                        exact_length = Some(len);
                    }
                }
                _ => {}
            }
        }

        let info_hash = info_hash.ok_or(MagnetError::MissingExactTopic)?;

        Ok(Self {
            info_hash,
            display_name,
            trackers,
            exact_length,
        })
    }

    /* decode 40-character hex or 32-character base32 info_hash into 20 bytes */
    pub fn decode_info_hash(hash_str: &str) -> Result<[u8; 20], MagnetError> {
        let clean = hash_str.trim();
        match clean.len() {
            40 => Self::decode_hex_info_hash(clean),
            32 => Self::decode_base32_info_hash(clean),
            len => Err(MagnetError::InvalidInfoHashLength(len)),
        }
    }

    /* decode 40-character hexadecimal representation */
    fn decode_hex_info_hash(hex_str: &str) -> Result<[u8; 20], MagnetError> {
        let mut hash = [0u8; 20];
        let bytes = hex_str.as_bytes();

        for i in 0..20 {
            let high = Self::hex_val(bytes[i * 2] as char)?;
            let low = Self::hex_val(bytes[i * 2 + 1] as char)?;
            hash[i] = (high << 4) | low;
        }

        Ok(hash)
    }

    /* map single ASCII character to 4-bit hexadecimal nibble */
    fn hex_val(c: char) -> Result<u8, MagnetError> {
        match c {
            '0'..='9' => Ok(c as u8 - b'0'),
            'a'..='f' => Ok(c as u8 - b'a' + 10),
            'A'..='F' => Ok(c as u8 - b'A' + 10),
            other => Err(MagnetError::InvalidInfoHashCharacter(other)),
        }
    }

    /* decode 32-character RFC 4648 Base32 representation (160 bits = 20 bytes) */
    fn decode_base32_info_hash(b32_str: &str) -> Result<[u8; 20], MagnetError> {
        let mut hash = [0u8; 20];
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;
        let mut byte_index = 0;

        for c in b32_str.chars() {
            let val = match c {
                'A'..='Z' => (c as u8 - b'A') as u64,
                'a'..='z' => (c as u8 - b'a') as u64,
                '2'..='7' => (c as u8 - b'2' + 26) as u64,
                other => return Err(MagnetError::InvalidInfoHashCharacter(other)),
            };

            buffer = (buffer << 5) | val;
            bits_in_buffer += 5;

            while bits_in_buffer >= 8 {
                bits_in_buffer -= 8;
                if byte_index < 20 {
                    hash[byte_index] = ((buffer >> bits_in_buffer) & 0xff) as u8;
                    byte_index += 1;
                }
            }
        }

        if byte_index != 20 {
            return Err(MagnetError::InvalidInfoHashLength(b32_str.len()));
        }

        Ok(hash)
    }

    /* percent-decode standard URL query parameter string */
    pub fn percent_decode(input: &str) -> String {
        let mut bytes = Vec::with_capacity(input.len());
        let mut chars = input.bytes();

        while let Some(b) = chars.next() {
            if b == b'%' {
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(c1), Some(c2)) = (h1, h2)
                    && let (Ok(n1), Ok(n2)) = (
                        Self::hex_val(c1 as char),
                        Self::hex_val(c2 as char),
                    )
                {
                    bytes.push((n1 << 4) | n2);
                    continue;
                }
                bytes.push(b'%');
            } else if b == b'+' {
                bytes.push(b' ');
            } else {
                bytes.push(b);
            }
        }

        String::from_utf8_lossy(&bytes).to_string()
    }

    /* format info_hash as lowercase 40-character hexadecimal string */
    pub fn info_hash_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for byte in &self.info_hash {
            use std::fmt::Write;
            write!(&mut s, "{:02x}", byte).unwrap();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_magnet_link() {
        let uri = "magnet:?xt=urn:btih:c12fe1c06bba254a9d1b00f12abb1f30c1d322ce&dn=Ubuntu+22.04&tr=http%3A%2F%2Ftracker.test%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.backup%3A1337";
        let magnet = MagnetLink::parse(uri).expect("magnet parsing failed");

        assert_eq!(
            magnet.info_hash_hex(),
            "c12fe1c06bba254a9d1b00f12abb1f30c1d322ce"
        );
        assert_eq!(magnet.display_name, Some("Ubuntu 22.04".to_string()));
        assert_eq!(magnet.trackers.len(), 2);
        assert_eq!(magnet.trackers[0], "http://tracker.test:6969/announce");
        assert_eq!(magnet.trackers[1], "udp://tracker.backup:1337");
    }

    #[test]
    fn test_parse_base32_magnet_link() {
        /* base32 info_hash corresponding to known 20 bytes */
        let uri = "magnet:?xt=urn:btih:YNCZ7PCLXISUVHJ3ADHQVKQ7GDCNGIXO&dn=SampleFile";
        let magnet = MagnetLink::parse(uri).expect("base32 magnet parsing failed");

        assert_eq!(magnet.display_name, Some("SampleFile".to_string()));
        assert_eq!(magnet.info_hash.len(), 20);
    }
}
