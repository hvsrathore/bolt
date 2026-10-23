/* parse BitTorrent metainfo (.torrent file) and extract cryptographic info_hash */

use crate::bencode::{parse, BencodeError};
use crate::sha1::{Sha1, SHA1_DIGEST_LENGTH};
use std::fmt;

/* errors encountered while deserializing BitTorrent metainfo */
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TorrentError {
    /* wrapped underlying Bencode parsing failure */
    Bencode(BencodeError),
    /* required dictionary key is missing */
    MissingField(&'static str),
    /* value encountered under key was not of expected type */
    InvalidFieldType(&'static str),
    /* piece hash byte string length is not a multiple of 20 bytes */
    InvalidPiecesLength(usize),
    /* multi-file file entry is malformed */
    InvalidFileEntry(&'static str),
    /* byte string failed UTF-8 string decoding */
    NonUtf8String(&'static str),
}

impl fmt::Display for TorrentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bencode(err) => write!(f, "Bencode error: {err}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidFieldType(field) => write!(f, "invalid data type for field: {field}"),
            Self::InvalidPiecesLength(len) => {
                write!(f, "invalid pieces byte length: {len} (must be multiple of 20)")
            }
            Self::InvalidFileEntry(reason) => write!(f, "invalid file entry: {reason}"),
            Self::NonUtf8String(field) => write!(f, "field '{field}' contains invalid UTF-8"),
        }
    }
}

impl std::error::Error for TorrentError {}

impl From<BencodeError> for TorrentError {
    fn from(err: BencodeError) -> Self {
        Self::Bencode(err)
    }
}

/* single file entry inside multi-file torrent */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo<'a> {
    pub length: u64,
    pub path: Vec<&'a str>,
}

impl<'a> FileInfo<'a> {
    /* concatenate path components with standard forward slashes */
    pub fn display_path(&self) -> String {
        self.path.join("/")
    }
}

/* file layout representation supporting both single-file and multi-file torrents */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTree<'a> {
    SingleFile {
        name: &'a str,
        length: u64,
    },
    MultiFile {
        directory_name: &'a str,
        files: Vec<FileInfo<'a>>,
    },
}

/* parsed BitTorrent metainfo structure borrowing strings and slices from source buffer */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metainfo<'a> {
    /* primary tracker announce URL */
    pub announce: &'a str,
    /* tiered backup tracker lists per BEP-0012 multitracker extension */
    pub announce_list: Vec<Vec<&'a str>>,
    /* nominal size of each piece in bytes (power of two, e.g. 262144) */
    pub piece_length: u64,
    /* concatenated 20-byte SHA-1 hashes of each consecutive file piece */
    pub pieces: &'a [u8],
    /* file tree describing either a single file or multiple hierarchical files */
    pub file_tree: FileTree<'a>,
    /* exact raw byte slice of the info dictionary in source buffer */
    pub info_bytes: &'a [u8],
    /* 20-byte SHA-1 cryptographic digest of the raw info dictionary */
    pub info_hash: [u8; SHA1_DIGEST_LENGTH],
}

impl<'a> Metainfo<'a> {
    /* parse .torrent file buffer into Metainfo, extracting file tree and computing info_hash */
    pub fn parse(buffer: &'a [u8]) -> Result<Self, TorrentError> {
        let root = parse(buffer)?;

        /* extract primary announce URL string */
        let announce_val = root
            .dict_get_by_str("announce")
            .ok_or(TorrentError::MissingField("announce"))?;
        let announce = announce_val
            .as_str()
            .ok_or(TorrentError::NonUtf8String("announce"))?;

        /* extract optional announce-list tiers per BEP-0012 */
        let mut announce_list = Vec::new();
        if let Some(tiers_val) = root.dict_get_by_str("announce-list")
            && let Some(tiers) = tiers_val.as_list()
        {
            for tier in tiers {
                if let Some(trackers) = tier.as_list() {
                    let mut tier_urls = Vec::new();
                    for tracker in trackers {
                        if let Some(url) = tracker.as_str() {
                            tier_urls.push(url);
                        }
                    }
                    if !tier_urls.is_empty() {
                        announce_list.push(tier_urls);
                    }
                }
            }
        }

        /* locate raw byte slice of the info dictionary for exact SHA-1 computation */
        let info_bytes = root
            .dict_get_raw_by_str("info")
            .ok_or(TorrentError::MissingField("info"))?;

        /* compute 20-byte SHA-1 info_hash directly over the unparsed canonical bytes */
        let info_hash = Sha1::digest(info_bytes);

        /* parse info dictionary contents */
        let info_val = root
            .dict_get_by_str("info")
            .ok_or(TorrentError::MissingField("info"))?;

        /* extract piece length integer */
        let piece_len_val = info_val
            .dict_get_by_str("piece length")
            .ok_or(TorrentError::MissingField("piece length"))?;
        let piece_length = piece_len_val
            .as_i64()
            .ok_or(TorrentError::InvalidFieldType("piece length"))? as u64;

        /* extract pieces raw byte string */
        let pieces_val = info_val
            .dict_get_by_str("pieces")
            .ok_or(TorrentError::MissingField("pieces"))?;
        let pieces = pieces_val
            .as_bytes()
            .ok_or(TorrentError::InvalidFieldType("pieces"))?;

        /* piece hash list must be exact multiple of 20 bytes (160-bit SHA-1) */
        if pieces.len() % SHA1_DIGEST_LENGTH != 0 {
            return Err(TorrentError::InvalidPiecesLength(pieces.len()));
        }

        /* extract primary file or directory name */
        let name_val = info_val
            .dict_get_by_str("name")
            .ok_or(TorrentError::MissingField("name"))?;
        let name = name_val
            .as_str()
            .ok_or(TorrentError::NonUtf8String("name"))?;

        /* determine if single-file or multi-file layout is employed */
        let file_tree = if let Some(files_val) = info_val.dict_get_by_str("files") {
            /* multi-file mode: parse 'files' list */
            let files_list = files_val
                .as_list()
                .ok_or(TorrentError::InvalidFieldType("files"))?;
            let mut files = Vec::with_capacity(files_list.len());

            for file_entry in files_list {
                let len_val = file_entry
                    .dict_get_by_str("length")
                    .ok_or(TorrentError::InvalidFileEntry("missing length in file entry"))?;
                let length = len_val
                    .as_i64()
                    .ok_or(TorrentError::InvalidFileEntry("invalid length type"))?
                    as u64;

                let path_val = file_entry
                    .dict_get_by_str("path")
                    .ok_or(TorrentError::InvalidFileEntry("missing path in file entry"))?;
                let path_list = path_val
                    .as_list()
                    .ok_or(TorrentError::InvalidFileEntry("path must be a list"))?;

                let mut path = Vec::with_capacity(path_list.len());
                for component in path_list {
                    let seg = component
                        .as_str()
                        .ok_or(TorrentError::InvalidFileEntry("path component is not UTF-8"))?;
                    path.push(seg);
                }

                files.push(FileInfo { length, path });
            }

            FileTree::MultiFile {
                directory_name: name,
                files,
            }
        } else if let Some(len_val) = info_val.dict_get_by_str("length") {
            /* single-file mode: length is directly in info dictionary */
            let length = len_val
                .as_i64()
                .ok_or(TorrentError::InvalidFieldType("length"))? as u64;

            FileTree::SingleFile { name, length }
        } else {
            return Err(TorrentError::MissingField("neither length nor files found"));
        };

        Ok(Metainfo {
            announce,
            announce_list,
            piece_length,
            pieces,
            file_tree,
            info_bytes,
            info_hash,
        })
    }

    /* calculate total payload size in bytes across all files */
    pub fn total_length(&self) -> u64 {
        match &self.file_tree {
            FileTree::SingleFile { length, .. } => *length,
            FileTree::MultiFile { files, .. } => files.iter().map(|f| f.length).sum(),
        }
    }

    /* return count of pieces contained in the torrent */
    pub fn piece_count(&self) -> usize {
        self.pieces.len() / SHA1_DIGEST_LENGTH
    }

    /* return 20-byte SHA-1 hash for specific piece index */
    pub fn piece_hash(&self, index: usize) -> Option<&'a [u8; SHA1_DIGEST_LENGTH]> {
        if index >= self.piece_count() {
            return None;
        }
        let offset = index * SHA1_DIGEST_LENGTH;
        let slice: &'a [u8; SHA1_DIGEST_LENGTH] = self.pieces[offset..offset + SHA1_DIGEST_LENGTH]
            .try_into()
            .expect("slice length verified to be 20 bytes");
        Some(slice)
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
    fn test_parse_single_file_torrent() {
        /* synthetic single-file .torrent buffer */
        let dummy_piece_hash = [0xabu8; 20];
        let mut torrent_data = Vec::new();
        torrent_data.extend_from_slice(b"d8:announce28:http://tracker.test/announce");
        torrent_data.extend_from_slice(b"13:announce-listll28:http://tracker.test/announceel27:http://backup.test/announceee");
        torrent_data.extend_from_slice(b"4:infod6:lengthi5242880e4:name10:ubuntu.iso12:piece lengthi262144e6:pieces20:");
        torrent_data.extend_from_slice(&dummy_piece_hash);
        torrent_data.extend_from_slice(b"ee");

        let metainfo = Metainfo::parse(&torrent_data).expect("metainfo parsing failed");

        assert_eq!(metainfo.announce, "http://tracker.test/announce");
        assert_eq!(
            metainfo.announce_list,
            vec![
                vec!["http://tracker.test/announce"],
                vec!["http://backup.test/announce"]
            ]
        );
        assert_eq!(metainfo.piece_length, 262144);
        assert_eq!(metainfo.piece_count(), 1);
        assert_eq!(metainfo.piece_hash(0), Some(&dummy_piece_hash));
        assert_eq!(metainfo.total_length(), 5242880);

        match &metainfo.file_tree {
            FileTree::SingleFile { name, length } => {
                assert_eq!(*name, "ubuntu.iso");
                assert_eq!(*length, 5242880);
            }
            _ => panic!("expected single-file layout"),
        }

        /* verify info_bytes and SHA-1 info_hash matches manual hash of info dict */
        let expected_info_hash = Sha1::digest(metainfo.info_bytes);
        assert_eq!(metainfo.info_hash, expected_info_hash);
    }

    #[test]
    fn test_parse_multi_file_torrent() {
        /* synthetic multi-file .torrent buffer */
        let dummy_pieces = [0x42u8; 40]; /* 2 pieces */
        let mut torrent_data = Vec::new();
        torrent_data.extend_from_slice(b"d8:announce28:http://tracker.test/announce");
        torrent_data.extend_from_slice(b"4:infod5:filesl");
        torrent_data.extend_from_slice(b"d6:lengthi100e4:pathl4:docs8:read.txtee");
        torrent_data.extend_from_slice(b"d6:lengthi200e4:pathl3:bin6:run.shee");
        torrent_data.extend_from_slice(b"e4:name7:my_proj12:piece lengthi16384e6:pieces40:");
        torrent_data.extend_from_slice(&dummy_pieces);
        torrent_data.extend_from_slice(b"ee");

        let metainfo = Metainfo::parse(&torrent_data).expect("metainfo parsing failed");

        assert_eq!(metainfo.total_length(), 300);
        assert_eq!(metainfo.piece_count(), 2);

        match &metainfo.file_tree {
            FileTree::MultiFile { directory_name, files } => {
                assert_eq!(*directory_name, "my_proj");
                assert_eq!(files.len(), 2);
                assert_eq!(files[0].length, 100);
                assert_eq!(files[0].display_path(), "docs/read.txt");
                assert_eq!(files[1].length, 200);
                assert_eq!(files[1].display_path(), "bin/run.sh");
            }
            _ => panic!("expected multi-file layout"),
        }
    }
}
