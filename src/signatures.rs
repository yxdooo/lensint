use regex::bytes::Regex;
use std::fs;
use std::path::Path;

pub fn scan_payloads(path: &Path) -> Vec<String> {
    let mut threats = Vec::new();
    
    // Read the file as raw bytes to avoid encoding issues with malicious payloads
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return threats,
    };

    // 1. PHP Webshell Injection (often hidden in EXIF or appended to image)
    let re_php = Regex::new(r"(?i)<\?php").unwrap();
    if re_php.is_match(&bytes) {
        threats.push("PHP_Webshell_Signature".to_string());
    }

    // 2. Embedded Executables (MZ header inside image, typical for Polyglot/Stego)
    // We check if "MZ" appears after the first 100 bytes (to avoid false positives if the image itself is an EXE, 
    // though this tool is meant for images).
    if bytes.len() > 100 {
        let re_mz = Regex::new(r"MZ").unwrap();
        if re_mz.is_match(&bytes[100..]) {
            threats.push("Embedded_MZ_Executable".to_string());
        }
    }

    // 3. Embedded Script tags
    let re_script = Regex::new(r"(?i)<script").unwrap();
    if re_script.is_match(&bytes) {
        threats.push("HTML_Script_Injection".to_string());
    }

    threats
}
