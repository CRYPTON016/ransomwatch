//! Webhook notification module
//!
//! Sends alerts to user-configured webhook endpoints.
//! Supports Slack, Discord, and generic JSON webhooks.
//!
//! IMPORTANT: Only sends to URLs YOU configure. NO TELEMETRY.

use serde::Serialize;
use tracing::{debug, warn};

use crate::monitor::{SecurityEvent, EventSeverity};

/// Webhook notification sender
#[cfg(feature = "webhook")]
pub struct WebhookNotifier {
    url: String,
    auth_header: Option<String>,
    retry_count: u32,
    client: reqwest::Client,
}

#[cfg(not(feature = "webhook"))]
pub struct WebhookNotifier {
    _private: (),
}

#[cfg(feature = "webhook")]
impl WebhookNotifier {
    /// Create a new webhook notifier
    pub fn new(url: String, auth_header: Option<String>, retry_count: u32) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            url,
            auth_header,
            retry_count,
            client,
        }
    }

    /// Send a security event to the webhook
    pub async fn send(&self, event: &SecurityEvent) -> Result<(), WebhookError> {
        let payload = self.format_payload(event);

        debug!("Sending webhook to: {}", self.url);

        let mut last_error = None;

        for attempt in 0..=self.retry_count {
            if attempt > 0 {
                warn!("Webhook retry attempt {}/{}", attempt, self.retry_count);
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
            }

            let mut request = self.client.post(&self.url);

            if let Some(ref auth) = self.auth_header {
                request = request.header("Authorization", auth);
            }

            match request.json(&payload).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        debug!("Webhook sent successfully");
                        return Ok(());
                    } else {
                        last_error = Some(WebhookError::HttpError(
                            response.status().as_u16(),
                            response.status().to_string(),
                        ));
                    }
                }
                Err(e) => {
                    last_error = Some(WebhookError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or(WebhookError::RequestFailed("Unknown error".to_string())))
    }

    /// Format the payload for the webhook
    fn format_payload(&self, event: &SecurityEvent) -> WebhookPayload {
        // Detect webhook type by URL pattern
        if self.url.contains("slack.com") {
            self.format_slack(event)
        } else if self.url.contains("discord.com") {
            self.format_discord(event)
        } else {
            self.format_generic(event)
        }
    }

    /// Format for Slack webhooks
    fn format_slack(&self, event: &SecurityEvent) -> WebhookPayload {
        let emoji = match event.severity {
            EventSeverity::Info => ":information_source:",
            EventSeverity::Warning => ":warning:",
            EventSeverity::Critical => ":rotating_light:",
        };

        let color = match event.severity {
            EventSeverity::Info => "#36a64f",
            EventSeverity::Warning => "#ff9800",
            EventSeverity::Critical => "#ff0000",
        };

        WebhookPayload::Slack(SlackPayload {
            text: format!("{} RansomWatch Alert - {}", emoji, event.severity),
            attachments: vec![SlackAttachment {
                color: color.to_string(),
                title: event.event_type.description(),
                text: format!(
                    "*Path:* {}\n*Time:* {}\n\n{}",
                    event.path.display(),
                    event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    event.recommendation
                ),
                footer: format!("Event ID: {}", event.id),
            }],
        })
    }

    /// Format for Discord webhooks
    fn format_discord(&self, event: &SecurityEvent) -> WebhookPayload {
        let color = match event.severity {
            EventSeverity::Info => 0x36a64f,
            EventSeverity::Warning => 0xff9800,
            EventSeverity::Critical => 0xff0000,
        };

        WebhookPayload::Discord(DiscordPayload {
            content: format!("🛡️ **RansomWatch Alert - {}**", event.severity),
            embeds: vec![DiscordEmbed {
                title: event.event_type.description(),
                description: format!(
                    "**Path:** {}\n**Time:** {}\n\n{}",
                    event.path.display(),
                    event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    event.recommendation
                ),
                color,
                footer: DiscordFooter {
                    text: format!("Event ID: {}", event.id),
                },
            }],
        })
    }

    /// Format for generic JSON webhooks
    fn format_generic(&self, event: &SecurityEvent) -> WebhookPayload {
        WebhookPayload::Generic(GenericPayload {
            alert_type: "ransomwatch".to_string(),
            severity: event.severity.to_string(),
            event_type: event.event_type.description(),
            path: event.path.display().to_string(),
            timestamp: event.timestamp.to_rfc3339(),
            recommendation: event.recommendation.clone(),
            event_id: event.id.clone(),
            context: event.context.clone(),
        })
    }

    /// Test the webhook connection
    pub async fn test(&self) -> Result<(), WebhookError> {
        let payload = WebhookPayload::Generic(GenericPayload {
            alert_type: "ransomwatch_test".to_string(),
            severity: "INFO".to_string(),
            event_type: "Test notification".to_string(),
            path: "/test".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            recommendation: "This is a test notification from RansomWatch".to_string(),
            event_id: "TEST-0000".to_string(),
            context: None,
        });

        let mut request = self.client.post(&self.url);

        if let Some(ref auth) = self.auth_header {
            request = request.header("Authorization", auth);
        }

        let response = request.json(&payload).send().await
            .map_err(|e| WebhookError::RequestFailed(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(WebhookError::HttpError(
                response.status().as_u16(),
                response.status().to_string(),
            ))
        }
    }
}

#[cfg(not(feature = "webhook"))]
impl WebhookNotifier {
    pub fn new(_url: String, _auth_header: Option<String>, _retry_count: u32) -> Self {
        Self { _private: () }
    }

    pub async fn send(&self, _event: &SecurityEvent) -> Result<(), WebhookError> {
        Err(WebhookError::NotEnabled)
    }

    pub async fn test(&self) -> Result<(), WebhookError> {
        Err(WebhookError::NotEnabled)
    }
}

/// Webhook payload types
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WebhookPayload {
    Slack(SlackPayload),
    Discord(DiscordPayload),
    Generic(GenericPayload),
}

#[derive(Debug, Serialize)]
struct SlackPayload {
    text: String,
    attachments: Vec<SlackAttachment>,
}

#[derive(Debug, Serialize)]
struct SlackAttachment {
    color: String,
    title: String,
    text: String,
    footer: String,
}

#[derive(Debug, Serialize)]
struct DiscordPayload {
    content: String,
    embeds: Vec<DiscordEmbed>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    footer: DiscordFooter,
}

#[derive(Debug, Serialize)]
struct DiscordFooter {
    text: String,
}

#[derive(Debug, Serialize)]
struct GenericPayload {
    alert_type: String,
    severity: String,
    event_type: String,
    path: String,
    timestamp: String,
    recommendation: String,
    event_id: String,
    context: Option<String>,
}

#[derive(Debug)]
pub enum WebhookError {
    RequestFailed(String),
    HttpError(u16, String),
    NotEnabled,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::RequestFailed(e) => write!(f, "Request failed: {}", e),
            WebhookError::HttpError(code, msg) => write!(f, "HTTP error {}: {}", code, msg),
            WebhookError::NotEnabled => write!(f, "Webhook feature not enabled"),
        }
    }
}

impl std::error::Error for WebhookError {}
