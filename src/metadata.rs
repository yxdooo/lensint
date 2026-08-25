use anyhow::Result;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExifData {
    pub make: Option<String>,
    pub model: Option<String>,
    pub software: Option<String>,
    pub datetime: Option<String>,
    pub raw_tags: HashMap<String, String>,
}

pub fn extract_exif(path: &Path) -> Result<ExifData> {
    let file = File::open(path)?;
    let mut bufreader = BufReader::new(&file);
    let exifreader = exif::Reader::new();
    
    let mut data = ExifData {
        make: None,
        model: None,
        software: None,
        datetime: None,
        raw_tags: HashMap::new(),
    };

    match exifreader.read_from_container(&mut bufreader) {
        Ok(exif) => {
            for f in exif.fields() {
                let tag = format!("{}", f.tag);
                let value = format!("{}", f.display_value().with_unit(&exif));
                
                match tag.as_str() {
                    "Make" => data.make = Some(value.clone()),
                    "Model" => data.model = Some(value.clone()),
                    "Software" => data.software = Some(value.clone()),
                    "DateTime" | "DateTimeOriginal" => {
                        if data.datetime.is_none() {
                            data.datetime = Some(value.clone());
                        }
                    },
                    _ => {}
                }
                data.raw_tags.insert(tag, value);
            }
        },
        Err(_) => {
            // No EXIF data found or unsupported format
        }
    }
    
    Ok(data)
}
