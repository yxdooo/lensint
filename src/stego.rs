use image::DynamicImage;
use std::collections::HashMap;

/// Calculates the Shannon Entropy of the Least Significant Bits (LSB).
/// Steganography tools (like embedding AES-encrypted payloads in images) 
/// randomize the LSBs, pushing the entropy close to 8.0.
pub fn calculate_lsb_entropy(img: &DynamicImage) -> f32 {
    let rgb = img.to_rgb8();
    let mut lsb_bytes = Vec::new();
    let mut current_byte = 0u8;
    let mut bit_count = 0;

    // Extract the LSB of every pixel's RGB channels and pack into bytes
    for pixel in rgb.pixels() {
        for c in 0..3 {
            let bit = pixel[c] & 1;
            current_byte = (current_byte << 1) | bit;
            bit_count += 1;

            if bit_count == 8 {
                lsb_bytes.push(current_byte);
                current_byte = 0;
                bit_count = 0;
            }
        }
    }

    if lsb_bytes.is_empty() {
        return 0.0;
    }

    // Calculate Shannon Entropy
    let mut frequencies = HashMap::new();
    for &byte in &lsb_bytes {
        *frequencies.entry(byte).or_insert(0) += 1;
    }

    let total = lsb_bytes.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in frequencies.values() {
        let p = count as f32 / total;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}
