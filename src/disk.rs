/* memory-mapped file storage and thread-pool piece verification using rayon and memmap2 */

use crate::sha1::Sha1;
use crate::torrent::{FileTree, Metainfo};
use memmap2::MmapMut;
use rayon::ThreadPool;
use std::fs::{create_dir_all, OpenOptions};
use std::path::{Path, PathBuf};

/* storage and I/O error variants for disk operations */
#[derive(Debug)]
pub enum DiskError {
    /* standard operating system file I/O failure */
    Io(std::io::Error),
    /* piece index out of bounds */
    InvalidPieceIndex { index: u32, total: usize },
    /* piece data length does not match expected size */
    InvalidPieceLength { expected: usize, actual: usize },
    /* piece data failed SHA-1 cryptographic digest verification */
    HashMismatch { index: u32 },
}

impl std::fmt::Display for DiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidPieceIndex { index, total } => {
                write!(f, "piece index {index} out of bounds (total pieces: {total})")
            }
            Self::InvalidPieceLength { expected, actual } => {
                write!(f, "piece length mismatch: expected {expected}, actual {actual}")
            }
            Self::HashMismatch { index } => {
                write!(f, "piece {index} failed SHA-1 cryptographic integrity verification")
            }
        }
    }
}

impl std::error::Error for DiskError {}

impl From<std::io::Error> for DiskError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/* single mapped target file segment within torrent global byte space */
pub struct MappedFile {
    pub path: PathBuf,
    pub offset_in_torrent: u64,
    pub length: u64,
    pub mmap: MmapMut,
}

/* disk manager coordinating zero-copy memory-mapped file writes and rayon hash checks */
pub struct DiskManager {
    piece_length: u64,
    total_length: u64,
    piece_hashes: Vec<[u8; 20]>,
    mapped_files: Vec<MappedFile>,
    thread_pool: ThreadPool,
}

impl DiskManager {
    /* construct disk manager for a single contiguous target file */
    pub fn new_single_file(
        target_path: &Path,
        total_length: u64,
        piece_length: u64,
        piece_hashes: Vec<[u8; 20]>,
        thread_pool: ThreadPool,
    ) -> Result<Self, DiskError> {
        if let Some(parent) = target_path.parent() {
            create_dir_all(parent)?;
        }

        /* open or create file with read/write permissions */
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(target_path)?;

        /* pre-allocate target file to exact torrent size to reserve contiguous storage */
        file.set_len(total_length)?;

        /* memory-map entire file into process virtual address space.
           safety note: exclusive write access is managed by the single-process coordinator */
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        let mapped_files = vec![MappedFile {
            path: target_path.to_path_buf(),
            offset_in_torrent: 0,
            length: total_length,
            mmap,
        }];

        Ok(Self {
            piece_length,
            total_length,
            piece_hashes,
            mapped_files,
            thread_pool,
        })
    }

    /* initialize disk manager from parsed BitTorrent metainfo, supporting multi-file trees */
    pub fn from_metainfo(
        base_dir: &Path,
        metainfo: &Metainfo,
        thread_pool: ThreadPool,
    ) -> Result<Self, DiskError> {
        let total_length = metainfo.total_length();
        let piece_length = metainfo.piece_length;

        let mut piece_hashes = Vec::with_capacity(metainfo.piece_count());
        for i in 0..metainfo.piece_count() {
            if let Some(hash) = metainfo.piece_hash(i) {
                piece_hashes.push(*hash);
            }
        }

        let mut mapped_files = Vec::new();
        let mut global_offset = 0u64;

        match &metainfo.file_tree {
            FileTree::SingleFile { name, length } => {
                let target_path = base_dir.join(name);
                if let Some(parent) = target_path.parent() {
                    create_dir_all(parent)?;
                }

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&target_path)?;

                file.set_len(*length)?;
                let mmap = unsafe { MmapMut::map_mut(&file)? };

                mapped_files.push(MappedFile {
                    path: target_path,
                    offset_in_torrent: 0,
                    length: *length,
                    mmap,
                });
            }
            FileTree::MultiFile {
                directory_name,
                files,
            } => {
                let root_dir = base_dir.join(directory_name);

                for file_info in files {
                    let mut file_path = root_dir.clone();
                    for component in &file_info.path {
                        file_path.push(component);
                    }

                    if let Some(parent) = file_path.parent() {
                        create_dir_all(parent)?;
                    }

                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&file_path)?;

                    file.set_len(file_info.length)?;
                    let mmap = unsafe { MmapMut::map_mut(&file)? };

                    mapped_files.push(MappedFile {
                        path: file_path,
                        offset_in_torrent: global_offset,
                        length: file_info.length,
                        mmap,
                    });

                    global_offset += file_info.length;
                }
            }
        }

        Ok(Self {
            piece_length,
            total_length,
            piece_hashes,
            mapped_files,
            thread_pool,
        })
    }

    /* verify 20-byte SHA-1 hash on dedicated rayon thread pool to prevent blocking async reactor */
    pub fn verify_hash_on_pool(&self, expected_hash: [u8; 20], data: &[u8]) -> bool {
        self.thread_pool.install(|| {
            let digest = Sha1::digest(data);
            digest == expected_hash
        })
    }

    /* calculate nominal byte length for specified piece index */
    pub fn piece_size(&self, piece_index: u32) -> Result<usize, DiskError> {
        let idx = piece_index as usize;
        if idx >= self.piece_hashes.len() {
            return Err(DiskError::InvalidPieceIndex {
                index: piece_index,
                total: self.piece_hashes.len(),
            });
        }

        let piece_start = piece_index as u64 * self.piece_length;
        let remaining = self.total_length.saturating_sub(piece_start);
        let size = std::cmp::min(self.piece_length, remaining) as usize;
        Ok(size)
    }

    /* verify piece hash on rayon pool and write payload across memory-mapped files */
    pub fn verify_and_write_piece(
        &mut self,
        piece_index: u32,
        data: &[u8],
    ) -> Result<(), DiskError> {
        let expected_size = self.piece_size(piece_index)?;
        if data.len() != expected_size {
            return Err(DiskError::InvalidPieceLength {
                expected: expected_size,
                actual: data.len(),
            });
        }

        let expected_hash = self.piece_hashes[piece_index as usize];

        /* offload CPU-intensive SHA-1 computation to rayon thread pool */
        let is_valid = self.verify_hash_on_pool(expected_hash, data);
        if !is_valid {
            return Err(DiskError::HashMismatch { index: piece_index });
        }

        /* write piece bytes directly into mapped memory regions */
        let piece_start = piece_index as u64 * self.piece_length;
        let piece_end = piece_start + data.len() as u64;

        for mapped_file in &mut self.mapped_files {
            let file_start = mapped_file.offset_in_torrent;
            let file_end = file_start + mapped_file.length;

            /* check if piece overlaps with this mapped file */
            if piece_start < file_end && piece_end > file_start {
                let overlap_start = std::cmp::max(piece_start, file_start);
                let overlap_end = std::cmp::min(piece_end, file_end);

                /* calculate offsets within source piece slice and destination memory map */
                let src_start = (overlap_start - piece_start) as usize;
                let src_end = (overlap_end - piece_start) as usize;

                let dst_start = (overlap_start - file_start) as usize;
                let dst_end = (overlap_end - file_start) as usize;

                /* direct memory copy to kernel page cache */
                mapped_file.mmap[dst_start..dst_end].copy_from_slice(&data[src_start..src_end]);

                /* flush memory-mapped changes to disk storage asynchronously */
                mapped_file.mmap.flush_async()?;
            }
        }

        Ok(())
    }

    /* read piece bytes from memory map for verification or seeding */
    pub fn read_piece(&self, piece_index: u32) -> Result<Vec<u8>, DiskError> {
        let size = self.piece_size(piece_index)?;
        let mut buffer = vec![0u8; size];

        let piece_start = piece_index as u64 * self.piece_length;
        let piece_end = piece_start + size as u64;

        for mapped_file in &self.mapped_files {
            let file_start = mapped_file.offset_in_torrent;
            let file_end = file_start + mapped_file.length;

            if piece_start < file_end && piece_end > file_start {
                let overlap_start = std::cmp::max(piece_start, file_start);
                let overlap_end = std::cmp::min(piece_end, file_end);

                let dst_start = (overlap_start - piece_start) as usize;
                let dst_end = (overlap_end - piece_start) as usize;

                let src_start = (overlap_start - file_start) as usize;
                let src_end = (overlap_end - file_start) as usize;

                buffer[dst_start..dst_end]
                    .copy_from_slice(&mapped_file.mmap[src_start..src_end]);
            }
        }

        Ok(buffer)
    }

    /* return reference to underlying rayon thread pool */
    pub fn thread_pool(&self) -> &ThreadPool {
        &self.thread_pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::ThreadPoolBuilder;
    use std::fs::read;

    #[test]
    fn test_disk_manager_single_file_write_and_verify() {
        let temp_dir = std::env::temp_dir().join(format!("bolt_test_{}", std::process::id()));
        let file_path = temp_dir.join("test_download.bin");

        let piece_length = 32 * 1024; /* 32 KiB pieces */
        let total_length = 80 * 1024; /* 2.5 pieces */

        /* synthesize payload */
        let mut synthetic_payload = Vec::with_capacity(total_length as usize);
        for i in 0..total_length {
            synthetic_payload.push((i % 253) as u8);
        }

        /* generate hashes for 3 pieces */
        let piece0 = &synthetic_payload[0..32768];
        let piece1 = &synthetic_payload[32768..65536];
        let piece2 = &synthetic_payload[65536..81920];

        let hashes = vec![
            Sha1::digest(piece0),
            Sha1::digest(piece1),
            Sha1::digest(piece2),
        ];

        let pool = ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("thread pool creation failed");

        let mut disk = DiskManager::new_single_file(
            &file_path,
            total_length,
            piece_length,
            hashes,
            pool,
        )
        .expect("disk manager initialization failed");

        /* write piece 1 first (out-of-order write) */
        disk.verify_and_write_piece(1, piece1)
            .expect("piece 1 write failed");

        /* write piece 0 */
        disk.verify_and_write_piece(0, piece0)
            .expect("piece 0 write failed");

        /* write piece 2 (short trailing piece) */
        disk.verify_and_write_piece(2, piece2)
            .expect("piece 2 write failed");

        /* read entire file back from disk filesystem to confirm persistence */
        let on_disk_bytes = read(&file_path).expect("read file failed");
        assert_eq!(on_disk_bytes, synthetic_payload);

        /* verify read_piece matches */
        assert_eq!(disk.read_piece(0).unwrap(), piece0);
        assert_eq!(disk.read_piece(1).unwrap(), piece1);
        assert_eq!(disk.read_piece(2).unwrap(), piece2);

        /* cleanup temp file and directory */
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_disk_manager_hash_mismatch_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("bolt_test_mismatch_{}", std::process::id()));
        let file_path = temp_dir.join("test_corrupt.bin");

        let piece_length = 16384;
        let total_length = 16384;
        let genuine_data = vec![0x42u8; piece_length as usize];
        let genuine_hash = Sha1::digest(&genuine_data);

        let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let mut disk = DiskManager::new_single_file(
            &file_path,
            total_length,
            piece_length,
            vec![genuine_hash],
            pool,
        )
        .unwrap();

        /* corrupt data payload */
        let mut corrupt_data = genuine_data.clone();
        corrupt_data[0] ^= 0xff;

        let result = disk.verify_and_write_piece(0, &corrupt_data);
        assert!(matches!(result, Err(DiskError::HashMismatch { index: 0 })));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }
}
