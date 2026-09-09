use std::env;
use std::net::SocketAddr;

use hoonarqube_service::{AuthConfig, Service};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = env::var("HOONARQUBE_SERVICE_DB")
        .unwrap_or_else(|_| "hoonarqube-service.sqlite3".to_string());
    let credentials = env::var("HOONARQUBE_SERVICE_CREDENTIALS")
        .map_err(|_| "HOONARQUBE_SERVICE_CREDENTIALS must be configured")?;
    let auth = AuthConfig::from_json(&credentials)?;
    let service = Service::open(database, auth)?;
    let bind: SocketAddr = env::var("HOONARQUBE_SERVICE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    let listener = TcpListener::bind(bind).await?;
    axum::serve(listener, service.router()).await?;
    Ok(())
}
