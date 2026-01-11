//! Alert modules for RansomWatch
//!
//! Handles sending alerts through various channels:
//! - Desktop notifications
//! - Webhooks (Slack, Discord, custom)
//! - Email
//!
//! ALL ALERTS ARE SENT ONLY TO USER-CONFIGURED ENDPOINTS.
//! NO TELEMETRY, NO PHONE HOME.

pub mod desktop;
pub mod webhook;
pub mod email;
pub mod logger;

use crate::config::AlertConfig;
use crate::monitor::SecurityEvent;
use tracing::{error, info};

pub use desktop::DesktopNotifier;
pub use webhook::WebhookNotifier;
pub use email::EmailNotifier;
pub use logger::FileLogger;

/// Alert manager that dispatches events to configured channels
pub struct AlertManager {
    desktop: Option<DesktopNotifier>,
    webhook: Option<WebhookNotifier>,
    email: Option<EmailNotifier>,
    logger: Option<FileLogger>,
}

impl AlertManager {
    /// Create a new alert manager from configuration
    pub fn new(config: &AlertConfig) -> Self {
        let desktop = if config.desktop {
            Some(DesktopNotifier::new())
        } else {
            None
        };

        let webhook = config.webhook.as_ref().map(|cfg| {
            WebhookNotifier::new(
                cfg.url.clone(),
                cfg.auth_header.clone(),
                cfg.retry_count,
            )
        });

        let email = config.email.as_ref().map(|cfg| {
            EmailNotifier::new(cfg.clone())
        });

        let logger = config.log_file.as_ref().map(|path| {
            FileLogger::new(path.clone())
        });

        Self {
            desktop,
            webhook,
            email,
            logger,
        }
    }

    /// Send an alert through all configured channels
    pub async fn send(&self, event: &SecurityEvent) {
        info!("Sending alert: {} - {}", event.severity, event.event_type.description());

        // Desktop notification
        if let Some(ref notifier) = self.desktop {
            if let Err(e) = notifier.send(event) {
                error!("Desktop notification failed: {}", e);
            }
        }

        // Webhook
        if let Some(ref notifier) = self.webhook {
            if let Err(e) = notifier.send(event).await {
                error!("Webhook notification failed: {}", e);
            }
        }

        // Email
        if let Some(ref notifier) = self.email {
            if let Err(e) = notifier.send(event).await {
                error!("Email notification failed: {}", e);
            }
        }

        // File logger
        if let Some(ref logger) = self.logger {
            if let Err(e) = logger.log(event) {
                error!("File logging failed: {}", e);
            }
        }
    }

    /// Check if any alert channels are configured
    pub fn has_channels(&self) -> bool {
        self.desktop.is_some() ||
        self.webhook.is_some() ||
        self.email.is_some() ||
        self.logger.is_some()
    }

    /// Get summary of configured channels
    pub fn channel_summary(&self) -> String {
        let mut channels = Vec::new();

        if self.desktop.is_some() {
            channels.push("desktop");
        }
        if self.webhook.is_some() {
            channels.push("webhook");
        }
        if self.email.is_some() {
            channels.push("email");
        }
        if self.logger.is_some() {
            channels.push("file");
        }

        if channels.is_empty() {
            "none".to_string()
        } else {
            channels.join(", ")
        }
    }
}
