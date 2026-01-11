//! File system watcher module
//!
//! Uses inotify (on Linux) to monitor file system events in real-time.
//! This is the core of RansomWatch's detection capability.

use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::{CreateKind, ModifyKind, RenameMode, RemoveKind},
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::WatchConfig;
use super::events::{EventSeverity, EventType, SecurityEvent};
use super::entropy::EntropyCalculator;
use super::patterns::PatternMatcher;

/// Tracks file operations for mass-operation detection
#[derive(Debug, Default)]
struct OperationTracker {
    /// Recent rename operations: (timestamp, old_path, new_path)
    renames: Vec<(Instant, PathBuf, PathBuf)>,
    /// Recent delete operations: (timestamp, path)
    deletes: Vec<(Instant, PathBuf)>,
    /// Recent high-entropy writes: (timestamp, path)
    high_entropy_writes: Vec<(Instant, PathBuf)>,
}

impl OperationTracker {
    fn new() -> Self {
        Self::default()
    }

    /// Clean up old entries outside the time window
    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.renames.retain(|(t, _, _)| *t > cutoff);
        self.deletes.retain(|(t, _)| *t > cutoff);
        self.high_entropy_writes.retain(|(t, _)| *t > cutoff);
    }

    /// Add a rename operation
    fn add_rename(&mut self, from: PathBuf, to: PathBuf) {
        self.renames.push((Instant::now(), from, to));
    }

    /// Add a delete operation
    fn add_delete(&mut self, path: PathBuf) {
        self.deletes.push((Instant::now(), path));
    }

    /// Add a high-entropy write
    fn add_high_entropy_write(&mut self, path: PathBuf) {
        self.high_entropy_writes.push((Instant::now(), path));
    }

    /// Get recent rename count
    fn rename_count(&self) -> usize {
        self.renames.len()
    }

    /// Get recent delete count
    fn delete_count(&self) -> usize {
        self.deletes.len()
    }

    /// Get sample of recently renamed files
    fn rename_samples(&self, count: usize) -> Vec<PathBuf> {
        self.renames
            .iter()
            .rev()
            .take(count)
            .map(|(_, _, to)| to.clone())
            .collect()
    }

    /// Get sample of recently deleted files
    fn delete_samples(&self, count: usize) -> Vec<PathBuf> {
        self.deletes
            .iter()
            .rev()
            .take(count)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

/// File system watcher for detecting ransomware activity
pub struct FileWatcher {
    /// Watch configuration
    config: WatchConfig,

    /// Pattern matcher for detecting suspicious filenames/extensions
    pattern_matcher: PatternMatcher,

    /// Entropy calculator
    entropy_calculator: EntropyCalculator,

    /// Detection thresholds
    entropy_threshold: f64,
    mass_op_count: u32,
    mass_op_window: Duration,
    min_file_size: u64,
    max_file_size: u64,
    entropy_sample_size: usize,

    /// Operation tracker for detecting mass operations
    tracker: Arc<RwLock<OperationTracker>>,
}

impl FileWatcher {
    /// Create a new file watcher
    pub fn new(config: WatchConfig, thresholds: &crate::config::ThresholdConfig) -> Self {
        Self {
            config,
            pattern_matcher: PatternMatcher::new(),
            entropy_calculator: EntropyCalculator::new(),
            entropy_threshold: thresholds.entropy_high,
            mass_op_count: thresholds.mass_operation_count,
            mass_op_window: Duration::from_secs(thresholds.mass_operation_window_secs),
            min_file_size: thresholds.min_file_size_bytes,
            max_file_size: thresholds.max_file_size_bytes,
            entropy_sample_size: thresholds.entropy_sample_size,
            tracker: Arc::new(RwLock::new(OperationTracker::new())),
        }
    }

    /// Start watching and return a channel for receiving security events
    pub async fn start(&self) -> Result<mpsc::Receiver<SecurityEvent>, WatcherError> {
        let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(1000);
        let (notify_tx, mut notify_rx) = mpsc::channel::<Result<Event, notify::Error>>(1000);

        // Create the file watcher
        let notify_tx_clone = notify_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = notify_tx_clone.blocking_send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(1)),
        ).map_err(|e| WatcherError::InitError(e.to_string()))?;

        // Add watch paths
        for path in &self.config.paths {
            if path.exists() {
                let mode = if self.config.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };

                watcher.watch(path, mode)
                    .map_err(|e| WatcherError::WatchError(path.clone(), e.to_string()))?;

                info!("Watching: {}", path.display());
            } else {
                warn!("Path does not exist, skipping: {}", path.display());
            }
        }

        // Clone necessary data for the async task
        let tracker = self.tracker.clone();
        let pattern_matcher = self.pattern_matcher.clone();
        let entropy_calculator = self.entropy_calculator.clone();
        let entropy_threshold = self.entropy_threshold;
        let mass_op_count = self.mass_op_count;
        let mass_op_window = self.mass_op_window;
        let min_file_size = self.min_file_size;
        let max_file_size = self.max_file_size;
        let entropy_sample_size = self.entropy_sample_size;
        let exclude_paths = self.config.exclude.clone();

        // Spawn the event processing task
        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            while let Some(res) = notify_rx.recv().await {
                match res {
                    Ok(event) => {
                        // Process the event
                        if let Some(security_event) = process_event(
                            &event,
                            &tracker,
                            &pattern_matcher,
                            &entropy_calculator,
                            entropy_threshold,
                            mass_op_count,
                            mass_op_window,
                            min_file_size,
                            max_file_size,
                            entropy_sample_size,
                            &exclude_paths,
                        ).await {
                            if event_tx.send(security_event).await.is_err() {
                                error!("Event channel closed");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Watch error: {}", e);
                    }
                }
            }
        });

        Ok(event_rx)
    }

    /// Check if a path should be excluded
    fn is_excluded(&self, path: &Path) -> bool {
        for exclude in &self.config.exclude {
            if let Some(pattern) = exclude.to_str() {
                if pattern.contains('*') {
                    // Glob pattern
                    if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                        if glob_pattern.matches_path(path) {
                            return true;
                        }
                    }
                } else if path.starts_with(exclude) {
                    return true;
                }
            }
        }
        false
    }
}

/// Process a file system event and return a security event if suspicious
async fn process_event(
    event: &Event,
    tracker: &Arc<RwLock<OperationTracker>>,
    pattern_matcher: &PatternMatcher,
    entropy_calculator: &EntropyCalculator,
    entropy_threshold: f64,
    mass_op_count: u32,
    mass_op_window: Duration,
    min_file_size: u64,
    max_file_size: u64,
    entropy_sample_size: usize,
    exclude_paths: &[PathBuf],
) -> Option<SecurityEvent> {
    // Get the primary path from the event
    let path = event.paths.first()?;

    // Check if excluded
    for exclude in exclude_paths {
        if let Some(pattern) = exclude.to_str() {
            if pattern.contains('*') {
                if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                    if glob_pattern.matches_path(path) {
                        return None;
                    }
                }
            } else if path.starts_with(exclude) {
                return None;
            }
        }
    }

    // Clean up old tracker entries
    {
        let mut tracker_guard = tracker.write().await;
        tracker_guard.cleanup(mass_op_window);
    }

    match &event.kind {
        // File created
        EventKind::Create(CreateKind::File) => {
            debug!("File created: {}", path.display());

            // Check for ransom note
            if let Some(note_type) = pattern_matcher.is_ransom_note(path) {
                return Some(SecurityEvent::new(
                    EventSeverity::Critical,
                    EventType::RansomNoteDetected { note_type },
                    path.clone(),
                ).with_context("A file matching known ransom note patterns was created"));
            }

            // Check for ransomware extension
            if let Some(ext) = pattern_matcher.is_ransomware_extension(path) {
                return Some(SecurityEvent::new(
                    EventSeverity::Critical,
                    EventType::RansomwareExtension {
                        extension: ext,
                        original_name: None,
                    },
                    path.clone(),
                ));
            }

            None
        }

        // File modified (content written)
        EventKind::Modify(ModifyKind::Data(_)) => {
            debug!("File modified: {}", path.display());

            // Check entropy for encryption detection
            if let Ok(metadata) = std::fs::metadata(path) {
                let size = metadata.len();

                if size >= min_file_size && size <= max_file_size {
                    if let Ok(entropy) = entropy_calculator.calculate_file(path, entropy_sample_size) {
                        if entropy >= entropy_threshold {
                            let mut tracker_guard = tracker.write().await;
                            tracker_guard.add_high_entropy_write(path.clone());

                            return Some(SecurityEvent::new(
                                EventSeverity::Warning,
                                EventType::HighEntropyWrite {
                                    entropy,
                                    file_size: size,
                                },
                                path.clone(),
                            ).with_context(format!(
                                "File entropy ({:.2}) exceeds threshold ({:.2}). May indicate encryption.",
                                entropy, entropy_threshold
                            )));
                        }
                    }
                }
            }

            None
        }

        // File renamed
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            if event.paths.len() >= 2 {
                let from = &event.paths[0];
                let to = &event.paths[1];

                debug!("File renamed: {} -> {}", from.display(), to.display());

                // Track the rename
                {
                    let mut tracker_guard = tracker.write().await;
                    tracker_guard.add_rename(from.clone(), to.clone());

                    // Check for mass rename
                    let count = tracker_guard.rename_count();
                    if count >= mass_op_count as usize {
                        let samples = tracker_guard.rename_samples(5);
                        return Some(SecurityEvent::new(
                            EventSeverity::Critical,
                            EventType::MassRename {
                                count: count as u32,
                                window_secs: mass_op_window.as_secs(),
                                sample_files: samples,
                            },
                            to.clone(),
                        ).with_context("Mass file rename detected - classic ransomware behavior"));
                    }
                }

                // Check for ransomware extension on the new name
                if let Some(ext) = pattern_matcher.is_ransomware_extension(to) {
                    let original = from.file_name()
                        .map(|n| n.to_string_lossy().to_string());

                    return Some(SecurityEvent::new(
                        EventSeverity::Critical,
                        EventType::RansomwareExtension {
                            extension: ext,
                            original_name: original,
                        },
                        to.clone(),
                    ).with_context(format!("File renamed from: {}", from.display())));
                }
            }

            None
        }

        // File deleted
        EventKind::Remove(RemoveKind::File) => {
            debug!("File deleted: {}", path.display());

            // Track the deletion
            {
                let mut tracker_guard = tracker.write().await;
                tracker_guard.add_delete(path.clone());

                // Check for mass deletion
                let count = tracker_guard.delete_count();
                if count >= mass_op_count as usize {
                    let samples = tracker_guard.delete_samples(5);
                    return Some(SecurityEvent::new(
                        EventSeverity::Critical,
                        EventType::MassDeletion {
                            count: count as u32,
                            window_secs: mass_op_window.as_secs(),
                            sample_files: samples,
                        },
                        path.clone(),
                    ).with_context("Mass file deletion detected"));
                }
            }

            None
        }

        _ => None,
    }
}

#[derive(Debug)]
pub enum WatcherError {
    InitError(String),
    WatchError(PathBuf, String),
}

impl std::fmt::Display for WatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatcherError::InitError(e) => write!(f, "Failed to initialize watcher: {}", e),
            WatcherError::WatchError(p, e) => write!(f, "Failed to watch {}: {}", p.display(), e),
        }
    }
}

impl std::error::Error for WatcherError {}
