//! Dashboard shared state

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::monitor::{SecurityEvent, EventSeverity};

/// Maximum number of events to keep in memory
const MAX_EVENTS: usize = 1000;

/// Dashboard statistics
#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub total_events: u64,
    pub critical_count: u64,
    pub warning_count: u64,
    pub info_count: u64,
    pub start_time: DateTime<Utc>,
    pub last_event_time: Option<DateTime<Utc>>,
    pub watched_paths: Vec<String>,
    pub uptime_secs: i64,
}

/// Shared state for the dashboard
#[derive(Clone)]
pub struct DashboardState {
    inner: Arc<RwLock<DashboardStateInner>>,
}

struct DashboardStateInner {
    events: VecDeque<SecurityEvent>,
    total_events: u64,
    critical_count: u64,
    warning_count: u64,
    info_count: u64,
    start_time: DateTime<Utc>,
    last_event_time: Option<DateTime<Utc>>,
    watched_paths: Vec<String>,
}

impl DashboardState {
    /// Create a new dashboard state
    pub fn new(watched_paths: Vec<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DashboardStateInner {
                events: VecDeque::with_capacity(MAX_EVENTS),
                total_events: 0,
                critical_count: 0,
                warning_count: 0,
                info_count: 0,
                start_time: Utc::now(),
                last_event_time: None,
                watched_paths,
            })),
        }
    }

    /// Add a new security event
    pub async fn add_event(&self, event: SecurityEvent) {
        let mut state = self.inner.write().await;

        // Update counters
        state.total_events += 1;
        match event.severity {
            EventSeverity::Critical => state.critical_count += 1,
            EventSeverity::Warning => state.warning_count += 1,
            EventSeverity::Info => state.info_count += 1,
        }

        state.last_event_time = Some(event.timestamp);

        // Add event to queue
        if state.events.len() >= MAX_EVENTS {
            state.events.pop_front();
        }
        state.events.push_back(event);
    }

    /// Get recent events
    pub async fn get_events(&self, limit: usize) -> Vec<SecurityEvent> {
        let state = self.inner.read().await;
        state.events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get dashboard statistics
    pub async fn get_stats(&self) -> DashboardStats {
        let state = self.inner.read().await;
        let now = Utc::now();

        DashboardStats {
            total_events: state.total_events,
            critical_count: state.critical_count,
            warning_count: state.warning_count,
            info_count: state.info_count,
            start_time: state.start_time,
            last_event_time: state.last_event_time,
            watched_paths: state.watched_paths.clone(),
            uptime_secs: (now - state.start_time).num_seconds(),
        }
    }

    /// Clear all events
    pub async fn clear_events(&self) {
        let mut state = self.inner.write().await;
        state.events.clear();
    }
}
