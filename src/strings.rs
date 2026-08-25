use anyhow::Result;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub fn extract_ascii_strings(path: &Path, min_length: usize) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    let mut strings = Vec::new();
    let mut current_string = String::new();

    for &byte in &buffer {
        if byte >= 32 && byte <= 126 {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_length {
                strings.push(current_string.clone());
            }
            current_string.clear();
        }
    }

    if current_string.len() >= min_length {
        strings.push(current_string);
    }

    Ok(strings)
}
