use std::fs;
use std::path::Path;

/// Simple native carver that scans a byte array for JPEG magic headers.
/// Useful for memory forensics (extracting embedded payload JPEGs from .vmem or .dmp)
/// and network forensics (PCAP carving) without needing external C-bindings.
pub fn carve_embedded_images(path: &Path) -> usize {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    let mut found = 0;
    let mut i = 0;
    let len = bytes.len();

    while i < len.saturating_sub(3) {
        // Look for JPEG Start of Image (FF D8 FF)
        if bytes[i] == 0xFF && bytes[i + 1] == 0xD8 && bytes[i + 2] == 0xFF {
            found += 1;
            // Jump ahead to avoid overlapping detections and speed up
            i += 10;
        } else {
            i += 1;
        }
    }

    found
}
