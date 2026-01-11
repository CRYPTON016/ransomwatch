//! Desktop notification module
//!
//! Sends native desktop notifications for security alerts.
//! Uses libnotify on Linux, native APIs on other platforms.

use notify_rust::{Notification, Urgency, Timeout};
use tracing::debug;

use crate::monitor::{SecurityEvent, EventSeverity};

/// Desktop notification sender
pub struct DesktopNotifier {
    app_name: String,
}

impl DesktopNotifier {
    /// Create a new desktop notifier
    pub fn new() -> Self {
        Self {
            app_name: "RansomWatch".to_string(),
        }
    }

    /// Send a desktop notification for a security event
    pub fn send(&self, event: &SecurityEvent) -> Result<(), NotifyError> {
        let (urgency, icon) = match event.severity {
            EventSeverity::Info => (Urgency::Low, "dialog-information"),
            EventSeverity::Warning => (Urgency::Normal, "dialog-warning"),
            EventSeverity::Critical => (Urgency::Critical, "dialog-error"),
        };

        let title = format!("🛡️ {} - {}", self.app_name, event.severity);

        let body = format!(
            "{}\n\nPath: {}\n\n{}",
            event.event_type.description(),
            event.path.display(),
            event.recommendation
        );

        debug!("Sending desktop notification: {}", title);

        Notification::new()
            .appname(&self.app_name)
            .summary(&title)
            .body(&body)
            .icon(icon)
            .urgency(urgency)
            .timeout(Timeout::Milliseconds(10000)) // 10 seconds
            .show()
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Send a test notification
    pub fn test(&self) -> Result<(), NotifyError> {
        Notification::new()
            .appname(&self.app_name)
            .summary("🛡️ RansomWatch - Test")
            .body("Desktop notifications are working!")
            .icon("dialog-information")
            .urgency(Urgency::Normal)
            .timeout(Timeout::Milliseconds(5000))
            .show()
            .map_err(|e| NotifyError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

impl Default for DesktopNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum NotifyError {
    SendFailed(String),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::SendFailed(e) => write!(f, "Failed to send notification: {}", e),
        }
    }
}

impl std::error::Error for NotifyError {}
