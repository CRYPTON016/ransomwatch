//! File logging module
//!
//! Logs security events to a local file for later analysis.
//! All data stays on your machine.

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;

use crate::monitor::SecurityEvent;

/// File logger for security events
pub struct FileLogger {
    path: PathBuf,
}

impl FileLogger {
    /// Create a new file logger
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Log a security event to the file
    pub fn log(&self, event: &SecurityEvent) -> Result<(), LogError> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent)
                .map_err(|e| LogError::IoError(e.to_string()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| LogError::IoError(e.to_string()))?;

        // Format as JSON line for easy parsing
        let json = serde_json::to_string(event)
            .map_err(|e| LogError::SerializeError(e.to_string()))?;

        writeln!(file, "{}", json)
            .map_err(|e| LogError::IoError(e.to_string()))?;

        debug!("Event logged to: {}", self.path.display());

        Ok(())
    }

    /// Log a formatted human-readable entry
    pub fn log_formatted(&self, event: &SecurityEvent) -> Result<(), LogError> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent)
                .map_err(|e| LogError::IoError(e.to_string()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| LogError::IoError(e.to_string()))?;

        writeln!(file, "{}", "=".repeat(80))
            .map_err(|e| LogError::IoError(e.to_string()))?;

        writeln!(file, "{}", event.format_alert())
            .map_err(|e| LogError::IoError(e.to_string()))?;

        writeln!(file, "")
            .map_err(|e| LogError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Get the log file path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[derive(Debug)]
pub enum LogError {
    IoError(String),
    SerializeError(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::IoError(e) => write!(f, "I/O error: {}", e),
            LogError::SerializeError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for LogError {}
