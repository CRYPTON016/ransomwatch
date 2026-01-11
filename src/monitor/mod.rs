//! Monitoring modules for RansomWatch
//!
//! This module contains all file system and process monitoring functionality.
//! Everything runs locally - NO TELEMETRY, NO PHONE HOME.

pub mod watcher;
pub mod entropy;
pub mod patterns;
pub mod process;
pub mod events;

pub use watcher::FileWatcher;
pub use entropy::EntropyCalculator;
pub use patterns::PatternMatcher;
pub use process::ProcessMonitor;
pub use events::{SecurityEvent, EventSeverity, EventType};
