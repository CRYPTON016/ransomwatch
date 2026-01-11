# RansomWatch

**Local-first ransomware detection for peace of mind.**

RansomWatch monitors your file system for ransomware activity and alerts you immediately. It's designed to detect threats early without blocking legitimate operations.

![Dashboard](docs/dashboard.png)

## Features

- **Entropy Detection** - Identifies encrypted files using Shannon entropy analysis
- **Pattern Matching** - Recognizes 95+ ransomware extensions and 40+ ransom note patterns
- **Mass Operation Detection** - Alerts on bulk file renames/deletions (common ransomware behavior)
- **Process Monitoring** - Watches for backup deletion commands (vssadmin, bcdedit, wbadmin)
- **Real-time Dashboard** - Visual web interface with threat level meter and activity charts
- **Multiple Alert Channels** - Desktop notifications, webhooks (Slack/Discord), email

## Philosophy

- **Monitor Only** - We detect and alert, we don't block. No false positives disrupting your work.
- **100% Local** - No telemetry, no cloud, no phone home. Your data stays on your machine.
- **Lightweight** - Minimal resource usage, runs quietly in the background.

## Installation

### From Source

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ransomwatch.git
cd ransomwatch

# Build
cargo build --release

# Install (optional)
sudo cp target/release/ransomwatch /usr/local/bin/
```

### Dependencies

- Rust 1.70+
- Linux (inotify), macOS (FSEvents), or Windows (ReadDirectoryChangesW) - *Currently Linux only*

## Quick Start

```bash
# Watch a directory
ransomwatch watch /home/user/Documents

# Watch with web dashboard
ransomwatch watch /home/user/Documents --dashboard

# Watch with custom dashboard port
ransomwatch watch /home/user/Documents --dashboard --dashboard-port 9000
```

## Usage

### Commands

```bash
# Initialize config file
ransomwatch init

# Watch directories (from config or CLI)
ransomwatch watch [PATHS...]

# Check a specific file's entropy
ransomwatch entropy <FILE>

# Scan for ransomware patterns
ransomwatch patterns <PATH>

# Test alert channels
ransomwatch test

# Check configuration
ransomwatch check
```

### Configuration

Create a config file at `~/.config/ransomwatch/config.toml`:

```toml
[watch]
paths = ["/home/user/Documents", "/home/user/Desktop"]
recursive = true
ignore_patterns = ["*.tmp", "*.log", ".git"]

[alerts]
desktop = true
webhook_url = "https://hooks.slack.com/services/XXX"
# email_to = "alerts@example.com"
# email_from = "ransomwatch@example.com"
# smtp_server = "smtp.example.com"

[thresholds]
entropy_threshold = 7.5        # 0-8 scale, 7.5+ indicates encryption
mass_operation_count = 50      # Alert after this many rapid operations
mass_operation_window_secs = 60
```

### Dashboard

The built-in dashboard provides real-time visualization:

- **Threat Level Meter** - Overall system risk assessment
- **Activity Chart** - Event timeline over last 30 seconds
- **Event Feed** - Live stream of detected threats
- **Statistics** - Total, critical, warning, info counts

Access at `http://127.0.0.1:8080` when running with `--dashboard`.

## Detection Methods

### Entropy Analysis

Files encrypted by ransomware have high entropy (randomness). RansomWatch calculates Shannon entropy:

| Entropy | Classification | Meaning |
|---------|---------------|---------|
| 0-3 | Very Low | Plain text, mostly zeros |
| 3-5 | Low | Normal text files |
| 5-6 | Medium | Compressed or binary |
| 6-7 | High | Highly compressed |
| 7-8 | Very High | Likely encrypted |

### Pattern Detection

Recognizes ransomware signatures:

- **Extensions**: `.lockbit`, `.encrypted`, `.ryuk`, `.conti`, `.wannacry`, `.cerber`, and 90+ more
- **Ransom Notes**: `README_DECRYPT.txt`, `RECOVER_FILES.html`, `!IMPORTANT!.txt`, and 40+ patterns
- **Processes**: `vssadmin delete shadows`, `bcdedit /set recoveryenabled no`, `wbadmin delete catalog`

### Mass Operations

Tracks file operation velocity. Alert triggers when:
- 50+ files renamed in 60 seconds
- 50+ files deleted in 60 seconds

## Alert Channels

### Desktop Notifications
Enabled by default. Uses system notification daemon.

### Webhooks (Slack/Discord)
```toml
[alerts]
webhook_url = "https://hooks.slack.com/services/T00/B00/XXX"
```

### Email
```toml
[alerts]
email_to = "security@yourcompany.com"
email_from = "ransomwatch@yourserver.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your@gmail.com"
smtp_password = "app-password"
```

## Roadmap

- [ ] Windows support
- [ ] macOS support
- [ ] Centralized multi-machine dashboard
- [ ] YARA rule integration
- [ ] Honeypot file deployment
- [ ] Automated backup triggers
- [ ] REST API for integrations

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).

## Disclaimer

RansomWatch is a detection tool, not a prevention tool. It helps you identify potential ransomware activity early but does not guarantee protection. Always maintain proper backups and follow security best practices.

---

**Built with Rust** | **100% Open Source** | **Zero Telemetry**
