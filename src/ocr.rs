use image::{DynamicImage, GenericImageView};

/// Custom Structural Text Region Detector (OCR Pre-processor).
/// Replaces external dependencies like Tesseract by using Pixel Projection Profiling 
/// and Sobel-like edge density to detect the presence of text in an image.
pub fn detect_text_regions(img: &DynamicImage) -> usize {
    let gray = img.to_luma8();
    let (w, h) = gray.dimensions();
    
    if w < 10 || h < 10 {
        return 0;
    }

    // Step 1: Horizontal Projection Profile (detect text lines)
    let mut row_density = vec![0u32; h as usize];
    
    // Calculate simple edge density (absolute difference from right neighbor)
    for y in 0..h {
        let mut density = 0;
        for x in 0..w - 1 {
            let p1 = gray.get_pixel(x, y)[0] as i32;
            let p2 = gray.get_pixel(x + 1, y)[0] as i32;
            let diff = (p1 - p2).abs();
            if diff > 30 { // Edge threshold
                density += 1;
            }
        }
        row_density[y as usize] = density;
    }

    // Step 2: Identify dense rows that likely contain text
    let mut text_lines = 0;
    let mut in_text_block = false;
    
    // A row is considered part of a text line if it has enough vertical edges
    let density_threshold = (w as f32 * 0.05) as u32; // at least 5% of width is edges
    
    for &density in &row_density {
        if density > density_threshold {
            if !in_text_block {
                in_text_block = true;
                text_lines += 1;
            }
        } else {
            in_text_block = false;
        }
    }

    text_lines
}
