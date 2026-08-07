//! `registryd`: the HTTP front end for an [`aqua_template_registry::Registry`].
//!
//! Configuration is environment variables only, because there is very little of
//! it and a config file would be one more thing to get out of sync:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `REGISTRY_DATA_DIR` | `./data` | Where the feed and tree blobs live |
//! | `REGISTRY_BIND` | `127.0.0.1:8088` | Listen address |
//! | `REGISTRY_ADDR_FILE` | unset | Write the bound address here once listening |
//!
//! `REGISTRY_ADDR_FILE` exists so a supervisor can bind port 0 and still learn
//! which port it got. The file is written after the listener is up, so its
//! appearance is also a readiness signal, and it is removed on clean shutdown.
//!
//! It binds loopback by default. Put it behind a reverse proxy for anything
//! reachable, and see the README on why there is no authentication here (there
//! is nothing to authenticate: every write is a signed tree that authenticates
//! itself).

use std::sync::Arc;

use aqua_template_registry::{http, Registry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::env::var("REGISTRY_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let bind = std::env::var("REGISTRY_BIND").unwrap_or_else(|_| "127.0.0.1:8088".to_string());

    let registry = Arc::new(Registry::open(&data_dir)?);
    let stats = registry.stats();

    println!("aqua-template-registry v{}", env!("CARGO_PKG_VERSION"));
    println!("  data dir : {data_dir}");
    println!(
        "  replayed : seq={} vendors={} templates={} aliases={} publishers={}",
        stats.head_seq, stats.vendors, stats.templates, stats.aliases, stats.publishers
    );

    let app = http::router(registry);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let addr = listener.local_addr()?;
    println!("  listening: http://{addr}");

    // Written only once the listener is bound, so a supervisor can treat the
    // file appearing as "the port is open", not merely "the process started".
    let addr_file = std::env::var("REGISTRY_ADDR_FILE").ok();
    if let Some(path) = &addr_file {
        std::fs::write(path, format!("{addr}\n"))?;
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    if let Some(path) = &addr_file {
        let _ = std::fs::remove_file(path);
    }
    println!("shutdown complete");
    Ok(())
}

/// Exit cleanly on Ctrl-C or SIGTERM, so a container stop is not a kill.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    println!("\nsignal received, shutting down");
}
