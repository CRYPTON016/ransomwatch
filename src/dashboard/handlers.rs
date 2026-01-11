//! HTTP request handlers for the dashboard

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
};
use serde::Deserialize;

use super::state::DashboardState;

/// Query parameters for events endpoint
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// GET /api/events - Get recent security events
pub async fn get_events(
    State(state): State<DashboardState>,
    Query(query): Query<EventsQuery>,
) -> impl IntoResponse {
    let events = state.get_events(query.limit).await;
    Json(events)
}

/// GET /api/stats - Get dashboard statistics
pub async fn get_stats(
    State(state): State<DashboardState>,
) -> impl IntoResponse {
    let stats = state.get_stats().await;
    Json(stats)
}

/// POST /api/clear - Clear all events
pub async fn clear_events(
    State(state): State<DashboardState>,
) -> impl IntoResponse {
    state.clear_events().await;
    StatusCode::OK
}

/// GET / - Serve the dashboard HTML
pub async fn index() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// Embedded dashboard HTML/CSS/JS - Visual Edition
const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RansomWatch Dashboard</title>
    <style>
        :root {
            --bg-dark: #0a0e14;
            --bg-card: #12171f;
            --bg-card-hover: #1a2030;
            --border: #1e2936;
            --text: #e6edf3;
            --text-dim: #7d8590;
            --critical: #ff4757;
            --critical-glow: rgba(255, 71, 87, 0.4);
            --warning: #ffa502;
            --warning-glow: rgba(255, 165, 2, 0.4);
            --info: #3742fa;
            --info-glow: rgba(55, 66, 250, 0.4);
            --success: #2ed573;
            --success-glow: rgba(46, 213, 115, 0.4);
            --accent: #7c3aed;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Animated background grid */
        .bg-grid {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image:
                linear-gradient(rgba(124, 58, 237, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(124, 58, 237, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 24px;
            position: relative;
            z-index: 1;
        }

        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding: 20px 28px;
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(124, 58, 237, 0.1) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .logo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent) 0%, #a855f7 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 4px 20px rgba(124, 58, 237, 0.4);
        }

        .logo h1 {
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .logo p {
            color: var(--text-dim);
            font-size: 13px;
            margin-top: 2px;
        }

        .status-section {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(46, 213, 115, 0.1);
            border: 1px solid rgba(46, 213, 115, 0.3);
            padding: 10px 20px;
            border-radius: 30px;
            font-weight: 600;
            font-size: 13px;
            color: var(--success);
        }

        .status-badge.offline {
            background: rgba(255, 71, 87, 0.1);
            border-color: rgba(255, 71, 87, 0.3);
            color: var(--critical);
        }

        .pulse-dot {
            width: 10px;
            height: 10px;
            background: var(--success);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-badge.offline .pulse-dot {
            background: var(--critical);
            animation: none;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }

        .uptime {
            color: var(--text-dim);
            font-size: 14px;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            border-color: var(--accent);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            border-radius: 16px 16px 0 0;
        }

        .stat-card.critical::before { background: var(--critical); }
        .stat-card.warning::before { background: var(--warning); }
        .stat-card.info::before { background: var(--info); }
        .stat-card.total::before { background: var(--accent); }

        .stat-icon {
            width: 56px;
            height: 56px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin-bottom: 16px;
        }

        .stat-card.critical .stat-icon {
            background: rgba(255, 71, 87, 0.15);
        }
        .stat-card.warning .stat-icon {
            background: rgba(255, 165, 2, 0.15);
        }
        .stat-card.info .stat-icon {
            background: rgba(55, 66, 250, 0.15);
        }
        .stat-card.total .stat-icon {
            background: rgba(124, 58, 237, 0.15);
        }

        .stat-card h3 {
            color: var(--text-dim);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 8px;
            font-weight: 500;
        }

        .stat-value {
            font-size: 42px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 8px;
        }

        .stat-card.critical .stat-value { color: var(--critical); }
        .stat-card.warning .stat-value { color: var(--warning); }
        .stat-card.info .stat-value { color: var(--info); }
        .stat-card.total .stat-value { color: var(--text); }

        .stat-bar {
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 12px;
        }

        .stat-bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.5s ease;
        }

        .stat-card.critical .stat-bar-fill { background: var(--critical); }
        .stat-card.warning .stat-bar-fill { background: var(--warning); }
        .stat-card.info .stat-bar-fill { background: var(--info); }
        .stat-card.total .stat-bar-fill { background: var(--accent); }

        /* Main Content Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 380px;
            gap: 24px;
        }

        /* Events Section */
        .events-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            background: rgba(124, 58, 237, 0.03);
        }

        .section-header h2 {
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-header h2 span {
            font-size: 20px;
        }

        .btn {
            background: var(--border);
            color: var(--text);
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn:hover {
            background: var(--accent);
            transform: translateY(-1px);
        }

        .events-list {
            max-height: 500px;
            overflow-y: auto;
        }

        .events-list::-webkit-scrollbar {
            width: 6px;
        }

        .events-list::-webkit-scrollbar-track {
            background: var(--bg-dark);
        }

        .events-list::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 3px;
        }

        .event {
            display: flex;
            gap: 16px;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            transition: all 0.2s;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }

        .event:hover {
            background: var(--bg-card-hover);
        }

        .event:last-child {
            border-bottom: none;
        }

        .event-indicator {
            width: 4px;
            border-radius: 2px;
            flex-shrink: 0;
        }

        .event-indicator.critical { background: var(--critical); box-shadow: 0 0 10px var(--critical-glow); }
        .event-indicator.warning { background: var(--warning); box-shadow: 0 0 10px var(--warning-glow); }
        .event-indicator.info { background: var(--info); box-shadow: 0 0 10px var(--info-glow); }

        .event-content {
            flex: 1;
            min-width: 0;
        }

        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }

        .event-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text);
        }

        .event-time {
            color: var(--text-dim);
            font-size: 12px;
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
        }

        .event-path {
            font-size: 13px;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
            background: var(--bg-dark);
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 8px;
        }

        .event-severity {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            padding: 4px 10px;
            border-radius: 4px;
            margin-top: 10px;
        }

        .event-severity.critical {
            background: rgba(255, 71, 87, 0.15);
            color: var(--critical);
        }

        .event-severity.warning {
            background: rgba(255, 165, 2, 0.15);
            color: var(--warning);
        }

        .event-severity.info {
            background: rgba(55, 66, 250, 0.15);
            color: var(--info);
        }

        .no-events {
            text-align: center;
            padding: 80px 20px;
            color: var(--text-dim);
        }

        .no-events-icon {
            width: 80px;
            height: 80px;
            background: rgba(46, 213, 115, 0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            margin: 0 auto 20px;
        }

        .no-events h3 {
            font-size: 18px;
            color: var(--text);
            margin-bottom: 8px;
        }

        /* Sidebar */
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* Activity Chart */
        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
        }

        .chart-card h3 {
            font-size: 16px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .chart {
            height: 120px;
            display: flex;
            align-items: flex-end;
            gap: 4px;
        }

        .chart-bar {
            flex: 1;
            background: linear-gradient(to top, var(--accent), rgba(124, 58, 237, 0.3));
            border-radius: 4px 4px 0 0;
            min-height: 4px;
            transition: height 0.5s ease;
        }

        .chart-bar.has-critical {
            background: linear-gradient(to top, var(--critical), rgba(255, 71, 87, 0.3));
        }

        .chart-bar.has-warning {
            background: linear-gradient(to top, var(--warning), rgba(255, 165, 2, 0.3));
        }

        .chart-labels {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            color: var(--text-dim);
            font-size: 11px;
        }

        /* Watched Paths */
        .paths-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
        }

        .paths-card h3 {
            font-size: 16px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .path-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: var(--bg-dark);
            border-radius: 8px;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }

        .path-icon {
            width: 32px;
            height: 32px;
            background: rgba(124, 58, 237, 0.15);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Threat Level */
        .threat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
        }

        .threat-card h3 {
            font-size: 16px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .threat-meter {
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 16px;
        }

        .threat-meter-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease, background 0.3s ease;
        }

        .threat-level {
            text-align: center;
            font-size: 24px;
            font-weight: 700;
        }

        .threat-level.low { color: var(--success); }
        .threat-level.medium { color: var(--warning); }
        .threat-level.high { color: var(--critical); }

        /* Responsive */
        @media (max-width: 1200px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
            .sidebar {
                flex-direction: row;
                flex-wrap: wrap;
            }
            .sidebar > * {
                flex: 1;
                min-width: 280px;
            }
        }

        @media (max-width: 900px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 600px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            header {
                flex-direction: column;
                gap: 16px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>

    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div>
                    <h1>RansomWatch</h1>
                    <p>Real-time Ransomware Detection</p>
                </div>
            </div>
            <div class="status-section">
                <div class="status-badge" id="status-badge">
                    <div class="pulse-dot"></div>
                    <span id="status-text">MONITORING</span>
                </div>
                <span class="uptime" id="uptime">--</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-icon">📊</div>
                <h3>Total Events</h3>
                <div class="stat-value" id="total-events">0</div>
                <div class="stat-bar">
                    <div class="stat-bar-fill" id="total-bar" style="width: 0%"></div>
                </div>
            </div>
            <div class="stat-card critical">
                <div class="stat-icon">🚨</div>
                <h3>Critical</h3>
                <div class="stat-value" id="critical-count">0</div>
                <div class="stat-bar">
                    <div class="stat-bar-fill" id="critical-bar" style="width: 0%"></div>
                </div>
            </div>
            <div class="stat-card warning">
                <div class="stat-icon">⚠️</div>
                <h3>Warning</h3>
                <div class="stat-value" id="warning-count">0</div>
                <div class="stat-bar">
                    <div class="stat-bar-fill" id="warning-bar" style="width: 0%"></div>
                </div>
            </div>
            <div class="stat-card info">
                <div class="stat-icon">ℹ️</div>
                <h3>Info</h3>
                <div class="stat-value" id="info-count">0</div>
                <div class="stat-bar">
                    <div class="stat-bar-fill" id="info-bar" style="width: 0%"></div>
                </div>
            </div>
        </div>

        <div class="main-grid">
            <div class="events-section">
                <div class="section-header">
                    <h2><span>📋</span> Live Events</h2>
                    <button class="btn" onclick="clearEvents()">
                        <span>🗑️</span> Clear All
                    </button>
                </div>
                <div class="events-list" id="events-list">
                    <div class="no-events">
                        <div class="no-events-icon">✓</div>
                        <h3>All Clear</h3>
                        <p>No suspicious activity detected</p>
                    </div>
                </div>
            </div>

            <div class="sidebar">
                <div class="threat-card">
                    <h3>🎯 Threat Level</h3>
                    <div class="threat-meter">
                        <div class="threat-meter-fill" id="threat-fill" style="width: 0%; background: var(--success)"></div>
                    </div>
                    <div class="threat-level low" id="threat-level">LOW</div>
                </div>

                <div class="chart-card">
                    <h3>📈 Activity (Last 30s)</h3>
                    <div class="chart" id="activity-chart"></div>
                    <div class="chart-labels">
                        <span>30s ago</span>
                        <span>Now</span>
                    </div>
                </div>

                <div class="paths-card">
                    <h3>📁 Watched Paths</h3>
                    <div id="watched-paths"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Activity history for chart
        const activityHistory = Array(30).fill({ count: 0, hasCritical: false, hasWarning: false });
        let lastEventCount = 0;

        // Format uptime
        function formatUptime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;

            if (hours > 0) {
                return `${hours}h ${minutes}m ${secs}s`;
            } else if (minutes > 0) {
                return `${minutes}m ${secs}s`;
            }
            return `${secs}s`;
        }

        // Format timestamp
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString('en-US', { hour12: false });
        }

        // Get event description
        function getEventDescription(eventType) {
            if (typeof eventType === 'string') return eventType;
            const key = Object.keys(eventType)[0];
            const data = eventType[key];
            switch (key) {
                case 'HighEntropyWrite':
                    return `High entropy write (${data.entropy.toFixed(2)} bits/byte)`;
                case 'MassRename':
                    return `Mass rename: ${data.count} files in ${data.window_secs}s`;
                case 'RansomwareExtension':
                    return `Ransomware extension: .${data.extension}`;
                case 'RansomNoteDetected':
                    return `Ransom note: ${data.note_type}`;
                case 'SuspiciousProcess':
                    return `Suspicious process: ${data.process_name}`;
                case 'BackupDeletionAttempt':
                    return `Backup deletion: ${data.method}`;
                case 'MassDeletion':
                    return `Mass deletion: ${data.count} files`;
                default:
                    return key;
            }
        }

        // Escape HTML
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Render events
        function renderEvents(events) {
            const container = document.getElementById('events-list');

            if (events.length === 0) {
                container.innerHTML = `
                    <div class="no-events">
                        <div class="no-events-icon">✓</div>
                        <h3>All Clear</h3>
                        <p>No suspicious activity detected</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = events.map(event => `
                <div class="event">
                    <div class="event-indicator ${event.severity.toLowerCase()}"></div>
                    <div class="event-content">
                        <div class="event-header">
                            <span class="event-title">${escapeHtml(getEventDescription(event.event_type))}</span>
                            <span class="event-time">${formatTime(event.timestamp)}</span>
                        </div>
                        <div class="event-path">${escapeHtml(event.path)}</div>
                        <span class="event-severity ${event.severity.toLowerCase()}">${event.severity}</span>
                    </div>
                </div>
            `).join('');
        }

        // Update activity chart
        function updateChart() {
            const container = document.getElementById('activity-chart');
            const maxCount = Math.max(...activityHistory.map(h => h.count), 1);

            container.innerHTML = activityHistory.map(h => {
                const height = Math.max((h.count / maxCount) * 100, 4);
                let className = 'chart-bar';
                if (h.hasCritical) className += ' has-critical';
                else if (h.hasWarning) className += ' has-warning';
                return `<div class="${className}" style="height: ${height}%"></div>`;
            }).join('');
        }

        // Update threat level
        function updateThreatLevel(stats) {
            const fill = document.getElementById('threat-fill');
            const level = document.getElementById('threat-level');

            let threatPercent = 0;
            let threatText = 'LOW';
            let threatColor = 'var(--success)';

            if (stats.critical_count > 0) {
                threatPercent = Math.min(50 + stats.critical_count * 10, 100);
                threatText = 'HIGH';
                threatColor = 'var(--critical)';
                level.className = 'threat-level high';
            } else if (stats.warning_count > 0) {
                threatPercent = Math.min(20 + stats.warning_count * 5, 49);
                threatText = 'MEDIUM';
                threatColor = 'var(--warning)';
                level.className = 'threat-level medium';
            } else {
                threatPercent = Math.min(stats.total_events, 19);
                level.className = 'threat-level low';
            }

            fill.style.width = `${threatPercent}%`;
            fill.style.background = threatColor;
            level.textContent = threatText;
        }

        // Fetch and update stats
        async function updateStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();

                document.getElementById('total-events').textContent = stats.total_events;
                document.getElementById('critical-count').textContent = stats.critical_count;
                document.getElementById('warning-count').textContent = stats.warning_count;
                document.getElementById('info-count').textContent = stats.info_count;
                document.getElementById('uptime').textContent = formatUptime(stats.uptime_secs);

                // Update bars
                const maxEvents = Math.max(stats.total_events, 1);
                document.getElementById('total-bar').style.width = '100%';
                document.getElementById('critical-bar').style.width = `${(stats.critical_count / maxEvents) * 100}%`;
                document.getElementById('warning-bar').style.width = `${(stats.warning_count / maxEvents) * 100}%`;
                document.getElementById('info-bar').style.width = `${(stats.info_count / maxEvents) * 100}%`;

                // Update paths
                const pathsContainer = document.getElementById('watched-paths');
                pathsContainer.innerHTML = stats.watched_paths.map(p => `
                    <div class="path-item">
                        <div class="path-icon">📂</div>
                        ${escapeHtml(p)}
                    </div>
                `).join('');

                // Update activity history
                const newEvents = stats.total_events - lastEventCount;
                activityHistory.shift();
                activityHistory.push({
                    count: newEvents,
                    hasCritical: stats.critical_count > (lastEventCount > 0 ? document.getElementById('critical-count').dataset.last || 0 : 0),
                    hasWarning: stats.warning_count > (lastEventCount > 0 ? document.getElementById('warning-count').dataset.last || 0 : 0)
                });
                document.getElementById('critical-count').dataset.last = stats.critical_count;
                document.getElementById('warning-count').dataset.last = stats.warning_count;
                lastEventCount = stats.total_events;

                updateChart();
                updateThreatLevel(stats);

                document.getElementById('status-badge').classList.remove('offline');
                document.getElementById('status-text').textContent = 'MONITORING';
            } catch (e) {
                document.getElementById('status-badge').classList.add('offline');
                document.getElementById('status-text').textContent = 'OFFLINE';
            }
        }

        // Fetch and update events
        async function updateEvents() {
            try {
                const response = await fetch('/api/events?limit=50');
                const events = await response.json();
                renderEvents(events);
            } catch (e) {
                console.error('Failed to fetch events:', e);
            }
        }

        // Clear events
        async function clearEvents() {
            try {
                await fetch('/api/clear', { method: 'POST' });
                lastEventCount = 0;
                updateEvents();
                updateStats();
            } catch (e) {
                console.error('Failed to clear events:', e);
            }
        }

        // Initialize chart
        updateChart();

        // Initial load and polling
        updateStats();
        updateEvents();
        setInterval(updateStats, 1000);
        setInterval(updateEvents, 1000);
    </script>
</body>
</html>
"##;
