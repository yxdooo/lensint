use image::{DynamicImage, GenericImageView};

/// Calculates the spatial frequency variance across 8x8 block boundaries vs internal pixels.
/// Digital forensics utilizes this because JPEG compression creates 8x8 grid boundaries. 
/// If an image is manipulated, the pasted region's grid will mismatch the original image's grid,
/// leading to an anomalous boundary-to-internal variance ratio.
pub fn calculate_grid_variance(img: &DynamicImage) -> f32 {
    let gray = img.to_luma8();
    let (w, h) = gray.dimensions();
    
    // We need a minimum size to detect blocks
    if w < 16 || h < 16 {
        return 0.0;
    }
    
    let mut boundary_diff: u64 = 0;
    let mut internal_diff: u64 = 0;
    let mut boundary_count: u64 = 0;
    let mut internal_count: u64 = 0;
    
    for y in 0..(h - 1) {
        for x in 0..(w - 1) {
            let p1 = gray.get_pixel(x, y)[0] as i32;
            let px = gray.get_pixel(x + 1, y)[0] as i32;
            let py = gray.get_pixel(x, y + 1)[0] as i32;
            
            let diff_x = (p1 - px).abs() as u64;
            let diff_y = (p1 - py).abs() as u64;
            
            // Check horizontal boundaries (x is multiple of 8)
            if (x + 1) % 8 == 0 {
                boundary_diff += diff_x;
                boundary_count += 1;
            } else {
                internal_diff += diff_x;
                internal_count += 1;
            }
            
            // Check vertical boundaries (y is multiple of 8)
            if (y + 1) % 8 == 0 {
                boundary_diff += diff_y;
                boundary_count += 1;
            } else {
                internal_diff += diff_y;
                internal_count += 1;
            }
        }
    }
    
    let avg_boundary = boundary_diff as f32 / (boundary_count as f32 + 1.0);
    let avg_internal = internal_diff as f32 / (internal_count as f32 + 1.0);
    
    if avg_internal < 0.1 {
        return 0.0; // Avoid division by zero on flat images
    }
    
    avg_boundary / avg_internal
}
