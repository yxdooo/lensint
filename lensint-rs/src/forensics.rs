use anyhow::{Context, Result};
use image::{DynamicImage, GenericImageView, ImageBuffer, Rgb, RgbImage};
use std::io::Cursor;

pub fn generate_ela(img: &DynamicImage, quality: u8, scale: f32) -> Result<RgbImage> {
    // Recompress image to JPEG in memory
    let mut buffer = Cursor::new(Vec::new());
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buffer, quality);
    encoder.encode(img.as_bytes(), img.width(), img.height(), img.color())
        .context("Failed to recompress image for ELA")?;
    
    // Load the recompressed image
    let recompressed_img = image::load_from_memory(buffer.get_ref())
        .context("Failed to load recompressed image")?;
    
    let (width, height) = img.dimensions();
    let mut ela_img = RgbImage::new(width, height);
    
    let orig_rgb = img.to_rgb8();
    let recomp_rgb = recompressed_img.to_rgb8();
    
    // Calculate the absolute difference and scale it
    for y in 0..height {
        for x in 0..width {
            let p1 = orig_rgb.get_pixel(x, y);
            let p2 = recomp_rgb.get_pixel(x, y);
            
            let diff_r = ((p1[0] as i16 - p2[0] as i16).abs() as f32 * scale).min(255.0) as u8;
            let diff_g = ((p1[1] as i16 - p2[1] as i16).abs() as f32 * scale).min(255.0) as u8;
            let diff_b = ((p1[2] as i16 - p2[2] as i16).abs() as f32 * scale).min(255.0) as u8;
            
            ela_img.put_pixel(x, y, Rgb([diff_r, diff_g, diff_b]));
        }
    }
    
    Ok(ela_img)
}

pub fn calculate_ela_score(ela_img: &RgbImage) -> f32 {
    let mut total_error: u64 = 0;
    let mut max_error: u8 = 0;
    
    for pixel in ela_img.pixels() {
        let max_chan = pixel[0].max(pixel[1]).max(pixel[2]);
        total_error += max_chan as u64;
        if max_chan > max_error {
            max_error = max_chan;
        }
    }
    
    let avg_error = total_error as f32 / (ela_img.width() * ela_img.height()) as f32;
    avg_error
}
