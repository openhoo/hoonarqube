//! Verify operator-visible rotation through a real service process on Unix.
#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = fs::remove_dir_all(&self.1);
    }
}

fn request(address: SocketAddr, token: &str, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(stream, "GET /api/v1/projects{path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").ok()?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).ok()?;
    reply.split_ascii_whitespace().nth(1)?.parse().ok()
}

fn wait_status(server: &mut Server, address: SocketAddr, token: &str, path: &str, expected: u16) {
    let start = Instant::now();
    loop {
        assert!(server.0.try_wait().unwrap().is_none(), "service exited");
        if request(address, token, path) == Some(expected) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "expected HTTP {expected} at {path}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn replace(path: &Path, source: &str) {
    let tmp = path.with_extension("new");
    fs::write(&tmp, source).unwrap();
    fs::rename(tmp, path).unwrap();
}

fn signal(server: &Server) {
    assert!(
        Command::new("kill")
            .args(["-HUP", &server.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn rotation_revokes_old_authority_and_recovers_after_an_invalid_file() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("hnq-rotate-{}-{unique}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("credentials.json");
    let first = r#"[{"user_id":"operator","token":"old","projects":{"alpha":"admin"}}]"#;
    let next = r#"[{"user_id":"operator","token":"new","projects":{"beta":"reader"}}]"#;
    replace(&path, first);
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_hoonarqube-service"))
        .env_remove("HOONARQUBE_SERVICE_CREDENTIALS")
        .env("HOONARQUBE_SERVICE_CREDENTIALS_FILE", &path)
        .env("HOONARQUBE_SERVICE_BIND", address.to_string())
        .env("HOONARQUBE_SERVICE_DB", directory.join("data.sqlite3"))
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server(child, directory);
    wait_status(&mut server, address, "old", "", 200);
    wait_status(&mut server, address, "new", "", 401);
    replace(&path, next);
    signal(&server);
    wait_status(&mut server, address, "old", "", 401);
    wait_status(&mut server, address, "new", "/alpha/branches", 403);
    wait_status(&mut server, address, "new", "", 200);
    replace(&path, "[");
    signal(&server);
    wait_status(&mut server, address, "new", "", 401);
    replace(&path, next);
    signal(&server);
    wait_status(&mut server, address, "new", "", 200);
    wait_status(&mut server, address, "old", "", 401);
}

#[test]
fn ambiguous_or_malformed_credentials_fail_before_opening_the_database() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("hnq-invalid-{}-{unique}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("credentials.json");
    let db = directory.join("must-not-open.sqlite3");
    let private_value = "not-a-role-and-not-for-logs";
    replace(
        &path,
        &format!(
            r#"[{{"user_id":"user","token":"value","projects":{{"alpha":"{private_value}"}}}}]"#
        ),
    );
    for ambiguous in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hoonarqube-service"));
        command
            .env_remove("HOONARQUBE_SERVICE_CREDENTIALS")
            .env("HOONARQUBE_SERVICE_CREDENTIALS_FILE", &path)
            .env("HOONARQUBE_SERVICE_DB", &db);
        if ambiguous {
            command.env("HOONARQUBE_SERVICE_CREDENTIALS", "[]");
        }
        let result = command.output().unwrap();
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(!result.status.success());
        assert!(error.contains(if ambiguous {
            "exactly one"
        } else {
            "invalid credentials JSON"
        }));
        assert!(!error.contains(private_value));
        assert!(!db.exists());
    }
    fs::remove_dir_all(directory).unwrap();
}
