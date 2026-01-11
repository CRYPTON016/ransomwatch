//! Configuration module for RansomWatch
//!
//! All settings are local - NO TELEMETRY, NO PHONE HOME.
//! The only external communication is to endpoints YOU configure.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Paths to watch for suspicious activity
    pub watch: WatchConfig,

    /// Alert configuration
    pub alerts: AlertConfig,

    /// Detection thresholds
    pub thresholds: ThresholdConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    /// Directories to monitor
    pub paths: Vec<PathBuf>,

    /// Paths to exclude from monitoring
    #[serde(default)]
    pub exclude: Vec<PathBuf>,

    /// Whether to watch subdirectories recursively
    #[serde(default = "default_recursive")]
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable desktop notifications
    #[serde(default = "default_true")]
    pub desktop: bool,

    /// Email address to send alerts (optional)
    /// Only sends to YOUR configured address - no external telemetry
    #[serde(default)]
    pub email: Option<EmailConfig>,

    /// Webhook URL for alerts (optional)
    /// Only sends to YOUR configured endpoint - no external telemetry
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,

    /// Log alerts to file
    #[serde(default)]
    pub log_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server address
    pub smtp_server: String,

    /// SMTP port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// SMTP username
    pub username: String,

    /// SMTP password (consider using environment variable)
    pub password: String,

    /// Email address to send from
    pub from: String,

    /// Email address to send alerts to
    pub to: String,

    /// Use TLS
    #[serde(default = "default_true")]
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL (your Slack, Discord, or custom endpoint)
    pub url: String,

    /// Optional authorization header
    #[serde(default)]
    pub auth_header: Option<String>,

    /// Retry count on failure
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Entropy threshold for detecting encrypted data (0.0 - 8.0)
    /// Normal files: ~4-6, Encrypted: ~7.5-8.0
    #[serde(default = "default_entropy_high")]
    pub entropy_high: f64,

    /// Number of file operations to trigger mass operation alert
    #[serde(default = "default_mass_op_count")]
    pub mass_operation_count: u32,

    /// Time window (seconds) for mass operation detection
    #[serde(default = "default_mass_op_window")]
    pub mass_operation_window_secs: u64,

    /// Minimum file size to check entropy (bytes)
    /// Skip tiny files to reduce false positives
    #[serde(default = "default_min_file_size")]
    pub min_file_size_bytes: u64,

    /// Maximum file size to check entropy (bytes)
    /// Skip huge files for performance
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,

    /// Sample size for entropy calculation (bytes)
    #[serde(default = "default_entropy_sample_size")]
    pub entropy_sample_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log to file path (optional)
    #[serde(default)]
    pub file: Option<PathBuf>,
}

// Default value functions
fn default_true() -> bool { true }
fn default_recursive() -> bool { true }
fn default_smtp_port() -> u16 { 587 }
fn default_retry_count() -> u32 { 3 }
fn default_entropy_high() -> f64 { 7.5 }
fn default_mass_op_count() -> u32 { 50 }
fn default_mass_op_window() -> u64 { 10 }
fn default_min_file_size() -> u64 { 1024 } // 1KB
fn default_max_file_size() -> u64 { 10 * 1024 * 1024 } // 10MB
fn default_entropy_sample_size() -> usize { 65536 } // 64KB
fn default_log_level() -> String { "info".to_string() }

impl Default for Config {
    fn default() -> Self {
        Self {
            watch: WatchConfig {
                paths: vec![],
                exclude: vec![],
                recursive: true,
            },
            alerts: AlertConfig {
                desktop: true,
                email: None,
                webhook: None,
                log_file: None,
            },
            thresholds: ThresholdConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            entropy_high: default_entropy_high(),
            mass_operation_count: default_mass_op_count(),
            mass_operation_window_secs: default_mass_op_window(),
            min_file_size_bytes: default_min_file_size(),
            max_file_size_bytes: default_max_file_size(),
            entropy_sample_size: default_entropy_sample_size(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadError(e.to_string()))?;

        toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Load configuration from default locations
    pub fn load_default() -> Result<Self, ConfigError> {
        let config_paths: Vec<PathBuf> = vec![
            Some(PathBuf::from("./ransomwatch.toml")),
            Some(PathBuf::from("./config.toml")),
            dirs_config_path(),
            Some(PathBuf::from("/etc/ransomwatch/config.toml")),
        ].into_iter().flatten().collect();

        for path in &config_paths {
            if path.exists() {
                return Self::load(path);
            }
        }

        Err(ConfigError::NotFound)
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        std::fs::write(path, content)
            .map_err(|e| ConfigError::WriteError(e.to_string()))
    }

    /// Generate example configuration
    pub fn example() -> Self {
        Self {
            watch: WatchConfig {
                paths: vec![
                    PathBuf::from("/home"),
                    PathBuf::from("/data"),
                    PathBuf::from("/var/www"),
                ],
                exclude: vec![
                    PathBuf::from("/home/*/.cache"),
                    PathBuf::from("/home/*/.local/share/Trash"),
                    PathBuf::from("*.tmp"),
                ],
                recursive: true,
            },
            alerts: AlertConfig {
                desktop: true,
                email: None,
                webhook: Some(WebhookConfig {
                    url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL".to_string(),
                    auth_header: None,
                    retry_count: 3,
                }),
                log_file: Some(PathBuf::from("/var/log/ransomwatch/alerts.log")),
            },
            thresholds: ThresholdConfig::default(),
            logging: LoggingConfig {
                level: "info".to_string(),
                file: Some(PathBuf::from("/var/log/ransomwatch/ransomwatch.log")),
            },
        }
    }
}

fn dirs_config_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home).join(".config/ransomwatch/config.toml")
    })
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound,
    ReadError(String),
    WriteError(String),
    ParseError(String),
    SerializeError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound => write!(f, "Configuration file not found"),
            ConfigError::ReadError(e) => write!(f, "Failed to read config: {}", e),
            ConfigError::WriteError(e) => write!(f, "Failed to write config: {}", e),
            ConfigError::ParseError(e) => write!(f, "Failed to parse config: {}", e),
            ConfigError::SerializeError(e) => write!(f, "Failed to serialize config: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}
