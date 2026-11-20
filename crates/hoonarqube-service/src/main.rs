use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use hoonarqube_service::{AuthConfig, Service};
use tokio::net::TcpListener;

fn load_auth() -> Result<(AuthConfig, Option<PathBuf>), Box<dyn std::error::Error>> {
    match (
        env::var_os("HOONARQUBE_SERVICE_CREDENTIALS"),
        env::var_os("HOONARQUBE_SERVICE_CREDENTIALS_FILE"),
    ) {
        (Some(json), None) => Ok((
            AuthConfig::from_json(json.to_str().ok_or("credentials must be UTF-8")?)?,
            None,
        )),
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            Ok((AuthConfig::from_file(&path)?, Some(path)))
        }
        _ => Err("configure exactly one of HOONARQUBE_SERVICE_CREDENTIALS and HOONARQUBE_SERVICE_CREDENTIALS_FILE".into()),
    }
}

#[cfg(unix)]
fn watch_credentials(auth: AuthConfig, path: PathBuf) -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut updates = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while updates.recv().await.is_some() {
            if auth.reload_file(path.clone()).await.is_ok() {
                eprintln!("service credentials reloaded");
            } else {
                eprintln!("service credential reload failed; access disabled");
            }
        }
    });
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = env::var("HOONARQUBE_SERVICE_DB")
        .unwrap_or_else(|_| "hoonarqube-service.sqlite3".to_string());
    let (auth, credential_path) = load_auth()?;
    #[cfg(unix)]
    if let Some(path) = credential_path {
        watch_credentials(auth.clone(), path)?;
    }
    #[cfg(not(unix))]
    let _ = credential_path;
    let service = Service::open(database, auth)?;
    let bind: SocketAddr = env::var("HOONARQUBE_SERVICE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    let listener = TcpListener::bind(bind).await?;
    axum::serve(listener, service.router()).await?;
    Ok(())
}
