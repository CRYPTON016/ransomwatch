//! Security event definitions
//!
//! Defines the types of events that RansomWatch can detect and alert on.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity level of a security event
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Informational - something happened but likely not malicious
    Info,
    /// Warning - suspicious activity detected, investigate
    Warning,
    /// Critical - high confidence malicious activity
    Critical,
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSeverity::Info => write!(f, "INFO"),
            EventSeverity::Warning => write!(f, "WARNING"),
            EventSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Type of security event detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    /// High entropy data written to file (possible encryption)
    HighEntropyWrite {
        entropy: f64,
        file_size: u64,
    },

    /// Mass file rename detected
    MassRename {
        count: u32,
        window_secs: u64,
        sample_files: Vec<PathBuf>,
    },

    /// Known ransomware extension detected
    RansomwareExtension {
        extension: String,
        original_name: Option<String>,
    },

    /// Ransom note file detected
    RansomNoteDetected {
        note_type: String,
    },

    /// Suspicious process detected (e.g., vssadmin, bcdedit)
    SuspiciousProcess {
        process_name: String,
        command_line: String,
        pid: u32,
    },

    /// Backup deletion attempt detected
    BackupDeletionAttempt {
        method: String,
        command: String,
    },

    /// Mass file deletion detected
    MassDeletion {
        count: u32,
        window_secs: u64,
        sample_files: Vec<PathBuf>,
    },

    /// File permission change detected
    PermissionChange {
        old_perms: String,
        new_perms: String,
    },

    /// Multiple indicators combined
    MultipleIndicators {
        indicators: Vec<String>,
    },
}

impl EventType {
    /// Get a human-readable description of the event type
    pub fn description(&self) -> String {
        match self {
            EventType::HighEntropyWrite { entropy, .. } => {
                format!("High entropy write detected ({:.2} bits/byte)", entropy)
            }
            EventType::MassRename { count, window_secs, .. } => {
                format!("{} files renamed in {} seconds", count, window_secs)
            }
            EventType::RansomwareExtension { extension, .. } => {
                format!("Known ransomware extension detected: {}", extension)
            }
            EventType::RansomNoteDetected { note_type } => {
                format!("Ransom note detected: {}", note_type)
            }
            EventType::SuspiciousProcess { process_name, .. } => {
                format!("Suspicious process: {}", process_name)
            }
            EventType::BackupDeletionAttempt { method, .. } => {
                format!("Backup deletion attempt via {}", method)
            }
            EventType::MassDeletion { count, window_secs, .. } => {
                format!("{} files deleted in {} seconds", count, window_secs)
            }
            EventType::PermissionChange { .. } => {
                "File permission change detected".to_string()
            }
            EventType::MultipleIndicators { indicators } => {
                format!("Multiple indicators: {}", indicators.join(", "))
            }
        }
    }
}

/// A security event detected by RansomWatch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID
    pub id: String,

    /// When the event was detected
    pub timestamp: DateTime<Utc>,

    /// Severity level
    pub severity: EventSeverity,

    /// Type of event
    pub event_type: EventType,

    /// Path to the affected file/directory
    pub path: PathBuf,

    /// Additional context
    pub context: Option<String>,

    /// Recommended action
    pub recommendation: String,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        severity: EventSeverity,
        event_type: EventType,
        path: PathBuf,
    ) -> Self {
        let recommendation = Self::get_recommendation(&event_type, &severity);

        Self {
            id: Self::generate_id(),
            timestamp: Utc::now(),
            severity,
            event_type,
            path,
            context: None,
            recommendation,
        }
    }

    /// Add context to the event
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Generate a unique event ID
    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!("RW-{:x}-{:x}", duration.as_secs(), duration.subsec_nanos())
    }

    /// Get recommended action based on event type
    fn get_recommendation(event_type: &EventType, severity: &EventSeverity) -> String {
        match (event_type, severity) {
            (EventType::HighEntropyWrite { .. }, EventSeverity::Critical) => {
                "Immediately investigate the process writing encrypted data. Consider isolating the system.".to_string()
            }
            (EventType::MassRename { .. }, EventSeverity::Critical) => {
                "Mass file rename detected - classic ransomware behavior. Check the source process immediately.".to_string()
            }
            (EventType::RansomwareExtension { .. }, _) => {
                "Known ransomware extension detected. Identify and stop the responsible process.".to_string()
            }
            (EventType::RansomNoteDetected { .. }, _) => {
                "Ransom note created - ransomware attack likely in progress or completed. Isolate system.".to_string()
            }
            (EventType::SuspiciousProcess { .. }, _) => {
                "Investigate this process. If unexpected, terminate it immediately.".to_string()
            }
            (EventType::BackupDeletionAttempt { .. }, _) => {
                "Backup deletion is a key ransomware tactic. Verify this is legitimate activity.".to_string()
            }
            (EventType::MassDeletion { .. }, _) => {
                "Mass file deletion detected. Verify this is intended and not malicious.".to_string()
            }
            (EventType::MultipleIndicators { .. }, _) => {
                "Multiple ransomware indicators detected. High likelihood of active attack. Take immediate action.".to_string()
            }
            _ => "Investigate this activity and determine if it is legitimate.".to_string()
        }
    }

    /// Format as a human-readable alert message
    pub fn format_alert(&self) -> String {
        let severity_icon = match self.severity {
            EventSeverity::Info => "ℹ️",
            EventSeverity::Warning => "⚠️",
            EventSeverity::Critical => "🚨",
        };

        let mut msg = format!(
            "{} RANSOMWATCH ALERT - {}\n\n",
            severity_icon, self.severity
        );

        msg.push_str(&format!("Event: {}\n", self.event_type.description()));
        msg.push_str(&format!("Path: {}\n", self.path.display()));
        msg.push_str(&format!("Time: {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));

        if let Some(ctx) = &self.context {
            msg.push_str(&format!("Details: {}\n", ctx));
        }

        msg.push_str(&format!("\nRecommendation: {}\n", self.recommendation));
        msg.push_str(&format!("\nEvent ID: {}", self.id));

        msg
    }

    /// Format as JSON for webhooks
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.format_alert())
    }
}
