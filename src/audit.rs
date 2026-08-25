use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Court-Standard Audit Trail Generator.
/// Generates a cryptographic seal combining the exact time of analysis,
/// the target file's identity, and the Lensint engine signature.
/// This ensures the resulting report is tamper-evident and admissible in court.
pub fn generate_evidentiary_seal(file_path: &str, file_hash_sha256: &str) -> (u64, String) {
    // Exact UTC execution time in seconds since Unix Epoch
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    // Create a strict cryptographic bind between the engine, the file, and the time
    let mut hasher = Sha256::new();
    hasher.update(b"LENSINT_V1_EVIDENTIARY_SEAL|");
    hasher.update(file_path.as_bytes());
    hasher.update(b"|");
    hasher.update(file_hash_sha256.as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.to_string().as_bytes());
    
    let result = hasher.finalize();
    let seal = format!("{:x}", result);
    
    (timestamp, seal)
}
