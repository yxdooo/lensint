mod crypto;
mod metadata;
mod forensics;

use clap::Parser;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target file or directory to analyze
    #[arg(short, long)]
    target: String,

    /// Output JSON report file
    #[arg(short, long, default_value = "report.json")]
    output: String,
}

#[derive(Debug, serde::Serialize)]
struct AnalysisResult {
    file_path: String,
    hashes: Option<crypto::FileHashes>,
    exif: Option<metadata::ExifData>,
    ela_score: Option<f32>,
    error: Option<String>,
}

fn process_file(path: &Path) -> AnalysisResult {
    let path_str = path.to_string_lossy().to_string();
    
    let hashes = match crypto::calculate_hashes(path) {
        Ok(h) => Some(h),
        Err(e) => {
            return AnalysisResult {
                file_path: path_str,
                hashes: None,
                exif: None,
                ela_score: None,
                error: Some(format!("Hash error: {}", e)),
            };
        }
    };

    let exif = match metadata::extract_exif(path) {
        Ok(e) => Some(e),
        Err(e) => {
            tracing::warn!("EXIF parsing failed for {:?}: {}", path, e);
            None
        }
    };

    let ela_score = match image::open(path) {
        Ok(img) => {
            match forensics::generate_ela(&img, 90, 15.0) {
                Ok(ela_img) => Some(forensics::calculate_ela_score(&ela_img)),
                Err(e) => {
                    tracing::warn!("ELA failed for {:?}: {}", path, e);
                    None
                }
            }
        },
        Err(e) => {
            tracing::warn!("Failed to open image for ELA {:?}: {}", path, e);
            None
        }
    };

    AnalysisResult {
        file_path: path_str,
        hashes,
        exif,
        ela_score,
        error: None,
    }
}

fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    info!("LENSINT 1.0 (Rust Engine) Initialized.");
    info!("Target: {}", args.target);

    let target_path = Path::new(&args.target);
    let mut files_to_process: Vec<PathBuf> = Vec::new();

    if target_path.is_file() {
        files_to_process.push(target_path.to_path_buf());
    } else if target_path.is_dir() {
        for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ["jpg", "jpeg", "png", "webp", "tif", "tiff"].contains(&ext_lower.as_str()) {
                        files_to_process.push(path.to_path_buf());
                    }
                }
            }
        }
    } else {
        anyhow::bail!("Target path does not exist.");
    }

    info!("Found {} supported images. Starting concurrent analysis...", files_to_process.len());

    let results: Vec<AnalysisResult> = files_to_process
        .par_iter()
        .map(|p| process_file(p))
        .collect();

    info!("Analysis complete. Writing report to {}", args.output);
    
    let json = serde_json::to_string_pretty(&results)?;
    std::fs::write(&args.output, json)?;

    Ok(())
}
