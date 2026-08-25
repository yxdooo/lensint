use image::{DynamicImage, GenericImageView};
use std::collections::HashMap;

/// Pure Rust implementation of Copy-Move Forgery Detection (CMFD).
/// Replaces the need for OpenCV ORB/RANSAC by utilizing a sliding-window 
/// Perceptual Average Hash (aHash) to identify cloned regions across an image.
pub fn detect_copy_move(img: &DynamicImage) -> usize {
    let gray = img.to_luma8();
    let (w, h) = gray.dimensions();
    let block_size = 32; // Analyze 32x32 pixel blocks
    let step = 16;       // Slide window by 16 pixels
    
    if w < block_size || h < block_size {
        return 0;
    }
    
    // Maps a perceptual hash to a list of (X, Y) coordinates where it was found
    let mut hash_map: HashMap<u64, Vec<(u32, u32)>> = HashMap::new();
    let mut clone_anomalies = 0;

    for y in (0..=h - block_size).step_by(step) {
        for x in (0..=w - block_size).step_by(step) {
            let hash = compute_ahash(&gray, x, y, block_size);
            
            let entry = hash_map.entry(hash).or_insert_with(Vec::new);
            
            // Check if this hash exists at a distant coordinate (ignoring adjacent blocks)
            let mut is_distant_clone = false;
            for &(ox, oy) in entry.iter() {
                let dist_sq = (ox as i32 - x as i32).pow(2) + (oy as i32 - y as i32).pow(2);
                let dist = (dist_sq as f32).sqrt();
                
                // If the same texture is found further than 2 block sizes away, it's a clone
                if dist > (block_size * 2) as f32 {
                    is_distant_clone = true;
                    break;
                }
            }
            
            if is_distant_clone {
                clone_anomalies += 1;
            }
            
            entry.push((x, y));
        }
    }
    
    clone_anomalies
}

/// Computes an 8x8 Average Hash (aHash) for a localized block to detect structural similarities.
fn compute_ahash(img: &image::GrayImage, start_x: u32, start_y: u32, size: u32) -> u64 {
    let mut pixels = [0u32; 64];
    let step = size / 8;
    let mut sum = 0;
    
    for i in 0..8 {
        for j in 0..8 {
            let px = img.get_pixel(start_x + (j * step), start_y + (i * step))[0] as u32;
            pixels[(i * 8 + j) as usize] = px;
            sum += px;
        }
    }
    
    let avg = sum / 64;
    let mut hash: u64 = 0;
    
    for (i, &px) in pixels.iter().enumerate() {
        if px > avg {
            hash |= 1 << i;
        }
    }
    
    hash
}
