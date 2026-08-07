//! Shared harness: temp directories and a real `registryd` child process.
//!
//! Compiled into every integration test that declares `mod common;`, so not
//! every item is used by every test binary.
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// A unique temporary directory that removes itself on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aqua-template-registry-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running `registryd` child process.
///
/// Binds port 0 and learns the assigned port from `REGISTRY_ADDR_FILE`, which
/// `registryd` writes only after the listener is up. That makes the file's
/// appearance a real readiness signal, so the tests need no sleep-and-hope.
pub struct RegistryDaemon {
    child: Option<Child>,
    data_dir: PathBuf,
    addr_file: PathBuf,
    base_url: String,
}

impl RegistryDaemon {
    /// Start a daemon against `data_dir` on an ephemeral port.
    pub fn start(data_dir: &Path) -> Self {
        let addr_file = data_dir.with_extension("addr");
        Self::spawn(data_dir.to_path_buf(), addr_file)
    }

    fn spawn(data_dir: PathBuf, addr_file: PathBuf) -> Self {
        let (child, base_url) = spawn_child(&data_dir, &addr_file);
        RegistryDaemon {
            child: Some(child),
            data_dir,
            addr_file,
            base_url,
        }
    }

    /// Base URL, for example `http://127.0.0.1:39481`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The data directory this daemon serves.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Stop with SIGTERM and wait for a clean exit.
    ///
    /// Returns the exit status. A daemon that has to be killed is a failure of
    /// the graceful-shutdown path, so tests assert on this.
    pub fn stop(&mut self) -> std::process::ExitStatus {
        let mut child = match self.child.take() {
            Some(c) => c,
            None => panic!("daemon already stopped"),
        };
        signal_term(&child);

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) if Instant::now() > deadline => {
                    let _ = child.kill();
                    panic!("registryd did not exit within 15s of SIGTERM");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("waiting on registryd: {e}"),
            }
        }
    }

    /// Stop and start again against the same data directory.
    ///
    /// The port changes, so callers must re-read `base_url`. That is deliberate:
    /// it forces a test to prove it is talking to the new process.
    pub fn restart(&mut self) {
        let status = self.stop();
        assert!(status.success(), "registryd exited with {status}");
        self.start_again();
    }

    /// Start again after an explicit `stop()`, against the same data directory.
    ///
    /// Separate from `restart` so a test can modify the data directory while
    /// the daemon is down, which is how a misbehaving registry is staged: the
    /// daemon stays honest, its data does not.
    pub fn start_again(&mut self) {
        assert!(self.child.is_none(), "daemon is still running");
        let (child, base_url) = spawn_child(&self.data_dir, &self.addr_file);
        self.child = Some(child);
        self.base_url = base_url;
    }
}

/// Start a `registryd` child and block until it reports its bound address.
fn spawn_child(data_dir: &Path, addr_file: &Path) -> (Child, String) {
    let _ = std::fs::remove_file(addr_file);
    std::fs::create_dir_all(data_dir).expect("create data dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_registryd"))
        .env("REGISTRY_DATA_DIR", data_dir)
        .env("REGISTRY_BIND", "127.0.0.1:0")
        .env("REGISTRY_ADDR_FILE", addr_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn registryd");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = std::fs::read_to_string(addr_file) {
            let addr = text.trim();
            if !addr.is_empty() {
                return (child, format!("http://{addr}"));
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "registryd exited early with {status}: {}",
                drain(&mut child)
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "registryd never wrote {}: {}",
                addr_file.display(),
                drain(&mut child)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Collect whatever the child wrote, for a useful panic message.
fn drain(child: &mut Child) -> String {
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut out);
    }
    out
}

impl Drop for RegistryDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            signal_term(&child);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() > deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break,
                }
            }
        }
        let _ = std::fs::remove_file(&self.addr_file);
    }
}

#[cfg(unix)]
fn signal_term(child: &Child) {
    // SIGTERM through libc would need an unsafe block, and the crate forbids
    // unsafe. `kill` is on every unix that runs this test suite.
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
}

#[cfg(not(unix))]
fn signal_term(_child: &Child) {}

/// Path to the committed seed set.
pub fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("seed/audit-set-v1")
}

/// The seed manifest, parsed.
pub fn seed_manifest() -> serde_json::Value {
    let text = std::fs::read_to_string(seed_dir().join("manifest.json")).expect("read manifest");
    serde_json::from_str(&text).expect("parse manifest")
}

/// The committed trust policy pinning the audit set publisher.
pub fn shipped_trust_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("trust/inblockio-audit-set-v1.json")
}

/// Publish the whole committed seed set through the HTTP API.
///
/// Registrations go to `/vendors` and `/templates`, definition bodies to
/// `/definitions`, all as raw bodies. Returns the publisher DID.
pub async fn publish_seed_over_http(
    client: &aqua_template_registry::httpclient::RegistryClient,
) -> String {
    let manifest = seed_manifest();
    let did = manifest["publisher_did"].as_str().expect("did").to_string();

    for entry in manifest["registrations"].as_array().expect("registrations") {
        let file = entry["tree_file"].as_str().expect("tree_file");
        let body = std::fs::read_to_string(seed_dir().join(file)).expect("read tree");

        let path = match entry["kind"].as_str().expect("kind") {
            "vendor" => "/vendors",
            "template" => "/templates",
            other => panic!("unexpected kind {other}"),
        };
        let response = client.post(path, body).await.expect("post registration");
        assert_eq!(
            response.status, 201,
            "POST {path} for {file} returned {}: {}",
            response.status, response.body
        );

        if let Some(def_file) = entry["definition_file"].as_str() {
            let def = std::fs::read_to_string(seed_dir().join(def_file)).expect("read definition");
            let response = client
                .post("/definitions", def)
                .await
                .expect("post definition");
            assert_eq!(
                response.status, 201,
                "POST /definitions for {def_file} returned {}: {}",
                response.status, response.body
            );
        }
    }

    did
}
