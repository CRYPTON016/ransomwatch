//! Web Dashboard for RansomWatch
//!
//! A lightweight embedded web dashboard for monitoring ransomware activity.
//! 100% LOCAL - serves only on localhost by default.

mod server;
mod handlers;
mod state;

pub use server::DashboardServer;
pub use state::DashboardState;
