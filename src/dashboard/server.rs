//! Dashboard HTTP server

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, error};

use super::handlers;
use super::state::DashboardState;

/// Dashboard web server
pub struct DashboardServer {
    state: DashboardState,
    port: u16,
}

impl DashboardServer {
    /// Create a new dashboard server
    pub fn new(state: DashboardState, port: u16) -> Self {
        Self { state, port }
    }

    /// Start the dashboard server
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/", get(handlers::index))
            .route("/api/events", get(handlers::get_events))
            .route("/api/stats", get(handlers::get_stats))
            .route("/api/clear", post(handlers::clear_events))
            .layer(cors)
            .with_state(self.state);

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));

        info!("Dashboard available at http://{}", addr);

        let listener = TcpListener::bind(addr).await?;

        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Start the dashboard server in the background
    pub fn start_background(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.start().await {
                error!("Dashboard server error: {}", e);
            }
        })
    }
}
