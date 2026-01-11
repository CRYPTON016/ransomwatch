//! Process monitoring module
//!
//! Monitors running processes for suspicious activity like:
//! - Backup deletion commands (vssadmin, wbadmin)
//! - Recovery disabling (bcdedit)
//! - Suspicious PowerShell commands

use std::collections::HashSet;
use std::time::Duration;
use sysinfo::{System, ProcessRefreshKind, RefreshKind};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use super::events::{EventSeverity, EventType, SecurityEvent};
use super::patterns::PatternMatcher;

/// Process monitor for detecting suspicious process activity
pub struct ProcessMonitor {
    /// Pattern matcher for identifying suspicious processes
    pattern_matcher: PatternMatcher,

    /// Polling interval
    poll_interval: Duration,

    /// Already alerted process IDs (to avoid duplicate alerts)
    alerted_pids: HashSet<u32>,
}

impl ProcessMonitor {
    /// Create a new process monitor
    pub fn new(poll_interval_secs: u64) -> Self {
        Self {
            pattern_matcher: PatternMatcher::new(),
            poll_interval: Duration::from_secs(poll_interval_secs),
            alerted_pids: HashSet::new(),
        }
    }

    /// Start monitoring and return a channel for security events
    pub async fn start(&self) -> mpsc::Receiver<SecurityEvent> {
        let (tx, rx) = mpsc::channel::<SecurityEvent>(100);
        let poll_interval = self.poll_interval;
        let pattern_matcher = self.pattern_matcher.clone();

        tokio::spawn(async move {
            let mut interval = interval(poll_interval);
            let mut alerted_pids: HashSet<u32> = HashSet::new();
            let mut sys = System::new();

            info!("Process monitor started with {}s polling interval", poll_interval.as_secs());

            loop {
                interval.tick().await;

                // Refresh process list
                sys.refresh_processes_specifics(
                    ProcessRefreshKind::new().with_cmd(sysinfo::UpdateKind::Always),
                );

                // Check each process
                for (pid, process) in sys.processes() {
                    let pid_u32 = pid.as_u32();

                    // Skip if already alerted
                    if alerted_pids.contains(&pid_u32) {
                        continue;
                    }

                    let name = process.name().to_string();
                    let cmd: Vec<String> = process.cmd().iter()
                        .map(|s| s.to_string())
                        .collect();
                    let cmd_line = cmd.join(" ");

                    // Check for suspicious process names
                    if pattern_matcher.is_suspicious_process(&name) {
                        debug!("Suspicious process detected: {} ({})", name, pid_u32);

                        // Check for backup deletion commands
                        if let Some(method) = pattern_matcher.is_backup_deletion_command(&cmd_line) {
                            alerted_pids.insert(pid_u32);

                            let event = SecurityEvent::new(
                                EventSeverity::Critical,
                                EventType::BackupDeletionAttempt {
                                    method: method.clone(),
                                    command: cmd_line.clone(),
                                },
                                std::path::PathBuf::from(&name),
                            ).with_context(format!(
                                "Process {} (PID {}) is attempting to delete backups",
                                name, pid_u32
                            ));

                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        } else {
                            // Generic suspicious process alert
                            alerted_pids.insert(pid_u32);

                            let event = SecurityEvent::new(
                                EventSeverity::Warning,
                                EventType::SuspiciousProcess {
                                    process_name: name.clone(),
                                    command_line: cmd_line.clone(),
                                    pid: pid_u32,
                                },
                                std::path::PathBuf::from(&name),
                            ).with_context(format!(
                                "Suspicious process activity detected. Review if this is expected."
                            ));

                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }

                    // Also check command line for backup deletion even if process name isn't suspicious
                    if !alerted_pids.contains(&pid_u32) {
                        if let Some(method) = pattern_matcher.is_backup_deletion_command(&cmd_line) {
                            alerted_pids.insert(pid_u32);

                            let event = SecurityEvent::new(
                                EventSeverity::Critical,
                                EventType::BackupDeletionAttempt {
                                    method,
                                    command: cmd_line.clone(),
                                },
                                std::path::PathBuf::from(&name),
                            ).with_context(format!(
                                "Process {} (PID {}) executing backup deletion command",
                                name, pid_u32
                            ));

                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }

                // Clean up old PIDs that no longer exist
                let current_pids: HashSet<u32> = sys.processes()
                    .keys()
                    .map(|p| p.as_u32())
                    .collect();

                alerted_pids.retain(|pid| current_pids.contains(pid));
            }
        });

        rx
    }

    /// Get a snapshot of currently running suspicious processes
    pub fn scan_once(&self) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        let mut sys = System::new();

        sys.refresh_processes_specifics(
            ProcessRefreshKind::new().with_cmd(sysinfo::UpdateKind::Always),
        );

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string();
            let cmd: Vec<String> = process.cmd().iter()
                .map(|s| s.to_string())
                .collect();
            let cmd_line = cmd.join(" ");

            if self.pattern_matcher.is_suspicious_process(&name) {
                if let Some(method) = self.pattern_matcher.is_backup_deletion_command(&cmd_line) {
                    events.push(SecurityEvent::new(
                        EventSeverity::Critical,
                        EventType::BackupDeletionAttempt {
                            method,
                            command: cmd_line.clone(),
                        },
                        std::path::PathBuf::from(&name),
                    ).with_context(format!("PID: {}", pid_u32)));
                } else {
                    events.push(SecurityEvent::new(
                        EventSeverity::Warning,
                        EventType::SuspiciousProcess {
                            process_name: name.clone(),
                            command_line: cmd_line,
                            pid: pid_u32,
                        },
                        std::path::PathBuf::from(&name),
                    ));
                }
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_monitor_creation() {
        let monitor = ProcessMonitor::new(5);
        assert_eq!(monitor.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_scan_once() {
        let monitor = ProcessMonitor::new(5);
        // This should run without panicking
        let _events = monitor.scan_once();
    }
}
