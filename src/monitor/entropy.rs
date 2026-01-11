//! Entropy calculation module
//!
//! Calculates Shannon entropy to detect encrypted/compressed data.
//! High entropy (>7.5) often indicates encryption - a key ransomware indicator.
//!
//! Optimized for performance with SIMD-friendly byte counting.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tracing::debug;

/// Shannon entropy calculator for ransomware detection
#[derive(Debug, Clone)]
pub struct EntropyCalculator {
    /// Precomputed log2 values for p*log2(p) calculation
    log_table: Vec<f64>,
}

impl Default for EntropyCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyCalculator {
    /// Create a new entropy calculator with precomputed lookup tables
    pub fn new() -> Self {
        // Precompute log2 table for faster calculation
        // log_table[n] = (n/256) * log2(n/256) for probability calculation
        let mut log_table = vec![0.0; 256 * 1024 + 1]; // Support up to 256KB samples

        for i in 1..log_table.len() {
            let p = i as f64;
            log_table[i] = p * p.log2();
        }

        Self { log_table }
    }

    /// Calculate entropy of a byte slice
    /// Returns entropy in bits per byte (0.0 to 8.0)
    ///
    /// - 0.0 = all same byte (no randomness)
    /// - ~4.5-6.0 = typical text/code
    /// - ~7.0-7.5 = compressed data
    /// - ~7.5-8.0 = encrypted/random data
    pub fn calculate(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Count byte frequencies
        let mut counts = [0u32; 256];

        // Process in chunks for better cache performance
        for chunk in data.chunks(8192) {
            for &byte in chunk {
                counts[byte as usize] += 1;
            }
        }

        // Calculate entropy using Shannon formula: -Σ p(x) * log2(p(x))
        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate entropy optimized for large buffers
    /// Uses lookup table for faster computation
    pub fn calculate_fast(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let len = data.len();

        // Count byte frequencies
        let mut counts = [0u32; 256];

        // Unrolled loop for better performance
        let chunks = data.chunks_exact(8);
        let remainder = chunks.remainder();

        for chunk in chunks {
            counts[chunk[0] as usize] += 1;
            counts[chunk[1] as usize] += 1;
            counts[chunk[2] as usize] += 1;
            counts[chunk[3] as usize] += 1;
            counts[chunk[4] as usize] += 1;
            counts[chunk[5] as usize] += 1;
            counts[chunk[6] as usize] += 1;
            counts[chunk[7] as usize] += 1;
        }

        for &byte in remainder {
            counts[byte as usize] += 1;
        }

        // Calculate entropy
        let len_f64 = len as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len_f64;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate entropy of a file (or sample of it)
    ///
    /// # Arguments
    /// * `path` - Path to the file
    /// * `sample_size` - Maximum bytes to read (0 = entire file)
    pub fn calculate_file(&self, path: &Path, sample_size: usize) -> Result<f64, EntropyError> {
        let file = File::open(path)
            .map_err(|e| EntropyError::IoError(e.to_string()))?;

        let metadata = file.metadata()
            .map_err(|e| EntropyError::IoError(e.to_string()))?;

        let file_size = metadata.len() as usize;

        if file_size == 0 {
            return Ok(0.0);
        }

        let read_size = if sample_size > 0 {
            sample_size.min(file_size)
        } else {
            file_size
        };

        let mut reader = BufReader::new(file);
        let mut buffer = vec![0u8; read_size];

        reader.read_exact(&mut buffer)
            .map_err(|e| EntropyError::IoError(e.to_string()))?;

        let entropy = self.calculate_fast(&buffer);

        debug!(
            "Entropy of {} ({} bytes sampled): {:.4}",
            path.display(),
            read_size,
            entropy
        );

        Ok(entropy)
    }

    /// Calculate entropy with streaming for very large files
    /// Samples multiple chunks throughout the file
    pub fn calculate_file_streaming(
        &self,
        path: &Path,
        chunk_size: usize,
        num_samples: usize,
    ) -> Result<f64, EntropyError> {
        use std::io::Seek;
        use std::io::SeekFrom;

        let mut file = File::open(path)
            .map_err(|e| EntropyError::IoError(e.to_string()))?;

        let metadata = file.metadata()
            .map_err(|e| EntropyError::IoError(e.to_string()))?;

        let file_size = metadata.len();

        if file_size == 0 {
            return Ok(0.0);
        }

        let actual_chunk_size = chunk_size.min(file_size as usize);
        let mut buffer = vec![0u8; actual_chunk_size];
        let mut total_counts = [0u64; 256];
        let mut total_bytes = 0u64;

        // Sample evenly throughout the file
        let step = if num_samples > 1 {
            file_size / num_samples as u64
        } else {
            0
        };

        for i in 0..num_samples {
            let offset = i as u64 * step;

            if offset >= file_size {
                break;
            }

            file.seek(SeekFrom::Start(offset))
                .map_err(|e| EntropyError::IoError(e.to_string()))?;

            let bytes_read = file.read(&mut buffer)
                .map_err(|e| EntropyError::IoError(e.to_string()))?;

            if bytes_read == 0 {
                break;
            }

            for &byte in &buffer[..bytes_read] {
                total_counts[byte as usize] += 1;
            }
            total_bytes += bytes_read as u64;
        }

        if total_bytes == 0 {
            return Ok(0.0);
        }

        // Calculate combined entropy
        let len_f64 = total_bytes as f64;
        let mut entropy = 0.0;

        for &count in &total_counts {
            if count > 0 {
                let p = count as f64 / len_f64;
                entropy -= p * p.log2();
            }
        }

        Ok(entropy)
    }

    /// Check if data appears to be encrypted based on entropy
    pub fn is_likely_encrypted(&self, data: &[u8], threshold: f64) -> bool {
        self.calculate_fast(data) >= threshold
    }

    /// Get entropy classification
    pub fn classify(&self, entropy: f64) -> EntropyClass {
        if entropy < 1.0 {
            EntropyClass::VeryLow
        } else if entropy < 4.0 {
            EntropyClass::Low
        } else if entropy < 6.0 {
            EntropyClass::Normal
        } else if entropy < 7.0 {
            EntropyClass::High
        } else if entropy < 7.5 {
            EntropyClass::Compressed
        } else {
            EntropyClass::Encrypted
        }
    }
}

/// Classification of entropy values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    /// Entropy < 1.0 - Repetitive data
    VeryLow,
    /// Entropy 1.0-4.0 - Simple structured data
    Low,
    /// Entropy 4.0-6.0 - Normal text/code
    Normal,
    /// Entropy 6.0-7.0 - Mixed or binary data
    High,
    /// Entropy 7.0-7.5 - Likely compressed
    Compressed,
    /// Entropy > 7.5 - Likely encrypted or random
    Encrypted,
}

impl std::fmt::Display for EntropyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyClass::VeryLow => write!(f, "Very Low (repetitive)"),
            EntropyClass::Low => write!(f, "Low (structured)"),
            EntropyClass::Normal => write!(f, "Normal (text/code)"),
            EntropyClass::High => write!(f, "High (binary)"),
            EntropyClass::Compressed => write!(f, "Compressed"),
            EntropyClass::Encrypted => write!(f, "Encrypted/Random"),
        }
    }
}

#[derive(Debug)]
pub enum EntropyError {
    IoError(String),
}

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for EntropyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let calc = EntropyCalculator::new();
        let data = vec![0u8; 1000]; // All zeros
        let entropy = calc.calculate(&data);
        assert!(entropy < 0.01, "Zero data should have ~0 entropy");
    }

    #[test]
    fn test_max_entropy() {
        let calc = EntropyCalculator::new();
        // Create data with uniform distribution
        let mut data = vec![0u8; 256 * 100];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }
        let entropy = calc.calculate(&data);
        assert!(entropy > 7.9, "Uniform distribution should have ~8 entropy");
    }

    #[test]
    fn test_text_entropy() {
        let calc = EntropyCalculator::new();
        let text = "Hello, World! This is some normal text that should have medium entropy.";
        let entropy = calc.calculate(text.as_bytes());
        assert!(entropy > 3.0 && entropy < 5.5, "Text should have medium entropy");
    }

    #[test]
    fn test_classification() {
        let calc = EntropyCalculator::new();
        assert_eq!(calc.classify(0.5), EntropyClass::VeryLow);
        assert_eq!(calc.classify(2.0), EntropyClass::Low);
        assert_eq!(calc.classify(5.0), EntropyClass::Normal);
        assert_eq!(calc.classify(6.5), EntropyClass::High);
        assert_eq!(calc.classify(7.2), EntropyClass::Compressed);
        assert_eq!(calc.classify(7.8), EntropyClass::Encrypted);
    }
}
