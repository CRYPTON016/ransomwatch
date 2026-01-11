//! RansomWatch - Lightweight Ransomware Activity Monitor
//!
//! A local-only security tool that monitors your file system for ransomware activity.
//!
//! IMPORTANT: This tool is 100% client-side. NO TELEMETRY, NO PHONE HOME.
//! The only external communication is to endpoints YOU explicitly configure.

mod config;
mod monitor;
mod alert;
mod dashboard;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::select;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use config::Config;
use monitor::{FileWatcher, ProcessMonitor, SecurityEvent, EventSeverity};
use alert::AlertManager;

/// RansomWatch - Local Ransomware Activity Monitor
#[derive(Parser)]
#[command(name = "ransomwatch")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "Lightweight ransomware activity monitor - alerts you before it's too late")]
#[command(long_about = r#"
RansomWatch monitors your file system for suspicious activity that may indicate
a ransomware attack. It watches for:

  • High entropy file writes (encryption detection)
  • Mass file renames with suspicious extensions
  • Known ransomware file extensions
  • Ransom note file creation
  • Backup deletion commands

PRIVACY: This tool runs 100% locally. No data is ever sent anywhere unless
you explicitly configure webhooks or email alerts to YOUR endpoints.
"#)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Paths to watch (can be specified multiple times)
    #[arg(short, long, value_name = "PATH")]
    watch: Vec<PathBuf>,

    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run in quiet mode (only critical alerts)
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start monitoring (default action)
    Watch {
        /// Paths to watch
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,

        /// Disable desktop notifications
        #[arg(long)]
        no_desktop: bool,

        /// Process monitoring poll interval in seconds
        #[arg(long, default_value = "5")]
        process_poll: u64,

        /// Enable web dashboard
        #[arg(long)]
        dashboard: bool,

        /// Dashboard port (default: 8080)
        #[arg(long, default_value = "8080")]
        dashboard_port: u16,
    },

    /// Generate a default configuration file
    Init {
        /// Output path for config file
        #[arg(short, long, default_value = "./ransomwatch.toml")]
        output: PathBuf,
    },

    /// Validate configuration file
    Check {
        /// Config file to validate
        #[arg(value_name = "FILE")]
        config: PathBuf,
    },

    /// Test alert channels
    Test {
        /// Test desktop notifications
        #[arg(long)]
        desktop: bool,

        /// Test webhook
        #[arg(long)]
        webhook: bool,

        /// Test email
        #[arg(long)]
        email: bool,

        /// Test all configured channels
        #[arg(long)]
        all: bool,
    },

    /// Scan a file for entropy
    Entropy {
        /// File to analyze
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Sample size in bytes (0 = entire file)
        #[arg(short, long, default_value = "65536")]
        sample: usize,
    },

    /// Show pattern database info
    Patterns,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Set up logging
    let log_level = if cli.quiet {
        Level::ERROR
    } else {
        match cli.verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    // Handle subcommands
    match cli.command {
        Some(Commands::Init { output }) => {
            init_config(&output);
        }
        Some(Commands::Check { config }) => {
            check_config(&config);
        }
        Some(Commands::Test { desktop, webhook, email, all }) => {
            test_alerts(desktop, webhook, email, all, &cli.config).await;
        }
        Some(Commands::Entropy { file, sample }) => {
            analyze_entropy(&file, sample);
        }
        Some(Commands::Patterns) => {
            show_patterns();
        }
        Some(Commands::Watch { paths, no_desktop, process_poll, dashboard, dashboard_port }) => {
            let config = load_config(&cli.config, &paths, !no_desktop);
            run_monitor(config, process_poll, dashboard, dashboard_port).await;
        }
        None => {
            // Default: start watching with dashboard enabled
            let config = load_config(&cli.config, &cli.watch, true);
            run_monitor(config, 5, true, 8080).await;
        }
    }
}

/// Load configuration from file or create default
fn load_config(config_path: &Option<PathBuf>, watch_paths: &[PathBuf], desktop: bool) -> Config {
    let mut config = if let Some(path) = config_path {
        match Config::load(path) {
            Ok(c) => {
                info!("Loaded config from: {}", path.display());
                c
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match Config::load_default() {
            Ok(c) => {
                info!("Loaded config from default location");
                c
            }
            Err(_) => {
                info!("No config file found, using defaults");
                Config::default()
            }
        }
    };

    // Override with CLI arguments
    if !watch_paths.is_empty() {
        config.watch.paths = watch_paths.to_vec();
    }

    config.alerts.desktop = desktop;

    config
}

/// Initialize a new configuration file
fn init_config(output: &PathBuf) {
    let config = Config::example();

    if output.exists() {
        error!("File already exists: {}", output.display());
        error!("Remove it first or choose a different path");
        std::process::exit(1);
    }

    match config.save(output) {
        Ok(_) => {
            println!("✓ Created configuration file: {}", output.display());
            println!();
            println!("Edit this file to configure:");
            println!("  - Paths to monitor");
            println!("  - Alert thresholds");
            println!("  - Notification channels (desktop, email, webhook)");
            println!();
            println!("Then run: ransomwatch --config {}", output.display());
        }
        Err(e) => {
            error!("Failed to create config file: {}", e);
            std::process::exit(1);
        }
    }
}

/// Check configuration file
fn check_config(path: &PathBuf) {
    match Config::load(path) {
        Ok(config) => {
            println!("✓ Configuration is valid");
            println!();
            println!("Watch paths: {}", config.watch.paths.len());
            for path in &config.watch.paths {
                println!("  - {}", path.display());
            }
            println!();
            println!("Thresholds:");
            println!("  Entropy threshold: {:.1}", config.thresholds.entropy_high);
            println!("  Mass operation count: {}", config.thresholds.mass_operation_count);
            println!("  Mass operation window: {}s", config.thresholds.mass_operation_window_secs);
            println!();
            println!("Alerts:");
            println!("  Desktop: {}", if config.alerts.desktop { "enabled" } else { "disabled" });
            println!("  Webhook: {}", if config.alerts.webhook.is_some() { "configured" } else { "not configured" });
            println!("  Email: {}", if config.alerts.email.is_some() { "configured" } else { "not configured" });
        }
        Err(e) => {
            error!("Invalid configuration: {}", e);
            std::process::exit(1);
        }
    }
}

/// Test alert channels
async fn test_alerts(desktop: bool, webhook: bool, email: bool, all: bool, config_path: &Option<PathBuf>) {
    let config = load_config(config_path, &[], true);

    if all || desktop {
        println!("Testing desktop notifications...");
        let notifier = alert::DesktopNotifier::new();
        match notifier.test() {
            Ok(_) => println!("  ✓ Desktop notifications working"),
            Err(e) => println!("  ✗ Desktop notifications failed: {}", e),
        }
    }

    if all || webhook {
        if let Some(ref wh_config) = config.alerts.webhook {
            println!("Testing webhook...");
            let notifier = alert::WebhookNotifier::new(
                wh_config.url.clone(),
                wh_config.auth_header.clone(),
                1,
            );
            match notifier.test().await {
                Ok(_) => println!("  ✓ Webhook working"),
                Err(e) => println!("  ✗ Webhook failed: {}", e),
            }
        } else {
            println!("  ⚠ Webhook not configured");
        }
    }

    if all || email {
        if let Some(ref email_config) = config.alerts.email {
            println!("Testing email...");
            let notifier = alert::EmailNotifier::new(email_config.clone());
            match notifier.test().await {
                Ok(_) => println!("  ✓ Email working"),
                Err(e) => println!("  ✗ Email failed: {}", e),
            }
        } else {
            println!("  ⚠ Email not configured");
        }
    }
}

/// Analyze file entropy
fn analyze_entropy(path: &PathBuf, sample_size: usize) {
    if !path.exists() {
        error!("File not found: {}", path.display());
        std::process::exit(1);
    }

    let calculator = monitor::EntropyCalculator::new();

    match calculator.calculate_file(path, sample_size) {
        Ok(entropy) => {
            let class = calculator.classify(entropy);
            println!("File: {}", path.display());
            println!("Entropy: {:.4} bits/byte", entropy);
            println!("Classification: {}", class);
            println!();

            if entropy >= 7.5 {
                println!("⚠️  HIGH ENTROPY - This file appears to be encrypted or random data.");
                println!("   This pattern is typical of ransomware-encrypted files.");
            } else if entropy >= 7.0 {
                println!("ℹ️  ELEVATED ENTROPY - This file may be compressed.");
            } else {
                println!("✓  Normal entropy level for typical file content.");
            }
        }
        Err(e) => {
            error!("Failed to analyze file: {}", e);
            std::process::exit(1);
        }
    }
}

/// Show pattern database info
fn show_patterns() {
    let matcher = monitor::PatternMatcher::new();
    let (ext_count, note_count, proc_count) = matcher.pattern_count();

    println!("RansomWatch Pattern Database");
    println!("============================");
    println!();
    println!("Known ransomware extensions: {}", ext_count);
    println!("Ransom note patterns: {}", note_count);
    println!("Suspicious process patterns: {}", proc_count);
    println!();
    println!("Sample extensions:");
    for ext in matcher.get_extensions().iter().take(20) {
        print!(".{} ", ext);
    }
    println!("...");
    println!();
    println!("The pattern database is updated with each release.");
    println!("Custom patterns can be added via the configuration file.");
}

/// Run the main monitoring loop
async fn run_monitor(config: Config, process_poll_secs: u64, enable_dashboard: bool, dashboard_port: u16) {
    // Validate we have paths to watch
    if config.watch.paths.is_empty() {
        error!("No paths configured to watch!");
        error!("Use --watch <path> or configure paths in config file");
        error!("Run 'ransomwatch init' to create a sample configuration");
        std::process::exit(1);
    }

    // Create alert manager
    let alert_manager = AlertManager::new(&config.alerts);

    // Create dashboard state
    let watched_paths: Vec<String> = config.watch.paths.iter()
        .map(|p| p.display().to_string())
        .collect();
    let dashboard_state = dashboard::DashboardState::new(watched_paths);

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║            🛡️  RANSOMWATCH - Local Security Monitor           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  100% Client-Side • No Telemetry • No Phone Home             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    info!("Starting RansomWatch...");
    info!("Alert channels: {}", alert_manager.channel_summary());

    // Start dashboard if enabled
    if enable_dashboard {
        let dashboard_server = dashboard::DashboardServer::new(
            dashboard_state.clone(),
            dashboard_port,
        );
        dashboard_server.start_background();
        info!("Dashboard: http://127.0.0.1:{}", dashboard_port);
    }

    // Start file watcher
    let file_watcher = FileWatcher::new(config.watch.clone(), &config.thresholds);
    let mut file_events = match file_watcher.start().await {
        Ok(rx) => rx,
        Err(e) => {
            error!("Failed to start file watcher: {}", e);
            std::process::exit(1);
        }
    };

    // Start process monitor
    let process_monitor = ProcessMonitor::new(process_poll_secs);
    let mut process_events = process_monitor.start().await;

    info!("Monitoring active. Press Ctrl+C to stop.");
    println!();

    // Set up Ctrl+C handler
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    // Main event loop
    loop {
        select! {
            // File system events
            Some(event) = file_events.recv() => {
                handle_event(&event, &alert_manager, &dashboard_state).await;
            }

            // Process events
            Some(event) = process_events.recv() => {
                handle_event(&event, &alert_manager, &dashboard_state).await;
            }

            // Ctrl+C
            _ = &mut ctrl_c => {
                println!();
                info!("Shutting down...");
                break;
            }
        }
    }

    println!("RansomWatch stopped.");
}

/// Handle a security event
async fn handle_event(event: &SecurityEvent, alert_manager: &AlertManager, dashboard_state: &dashboard::DashboardState) {
    // Log to console
    let prefix = match event.severity {
        EventSeverity::Info => "ℹ️ ",
        EventSeverity::Warning => "⚠️ ",
        EventSeverity::Critical => "🚨",
    };

    println!(
        "{} [{}] {} - {}",
        prefix,
        event.timestamp.format("%H:%M:%S"),
        event.severity,
        event.event_type.description()
    );
    println!("   Path: {}", event.path.display());

    if let Some(ref ctx) = event.context {
        println!("   Details: {}", ctx);
    }

    println!();

    // Add to dashboard
    dashboard_state.add_event(event.clone()).await;

    // Send alerts
    alert_manager.send(event).await;
}
