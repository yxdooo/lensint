use anyhow::Result;
use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Digest as Sha2Digest};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    pub file_size: u64,
}

pub fn calculate_hashes(path: &Path) -> Result<FileHashes> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        md5_hasher.update(&buffer[..count]);
        sha256_hasher.update(&buffer[..count]);
    }

    Ok(FileHashes {
        md5: format!("{:x}", md5_hasher.finalize()),
        sha256: format!("{:x}", sha256_hasher.finalize()),
        file_size,
    })
}
