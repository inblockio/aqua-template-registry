//! `subscribe`: follow a publisher, verify what they publish, import it locally.
//!
//! ```text
//! subscribe --registry URL --publisher DID --trust PATH [--store PATH]
//!           [--cursor PATH] [--approve-new] [--once] [--interval SECS]
//! ```
//!
//! | Flag | Default | Meaning |
//! |---|---|---|
//! | `--registry` | `http://127.0.0.1:8088` | Registry to poll |
//! | `--publisher` | required | Publisher DID to follow |
//! | `--trust` | required | Trust policy JSON (see `trust/`) |
//! | `--store` | `./imported` | Where verified templates land |
//! | `--cursor` | `<store>/cursor.json` | Persisted feed position |
//! | `--approve-new` | off | Import and pin templates that are not yet pinned |
//! | `--once` | off | Poll once and exit instead of looping |
//! | `--interval` | `30` | Seconds between polls when looping |
//! | `--list` | off | Print the local store and exit, polling nothing |
//!
//! # Why `--approve-new` is a flag and not a config setting
//!
//! Pinning is the control that stops a publisher you already trust from
//! swapping a template underneath you. Turning it off has to be a deliberate,
//! visible act at the moment of doing it, not a line in a file that someone set
//! months ago and nobody rereads. Without the flag, a template that is not
//! pinned is refused, and the run says so. With it, the template is imported
//! AND appended to the trust file, so every accepted template ends up durably
//! recorded and reviewable in a diff.
//!
//! Even with the flag, a name that is pinned to a DIFFERENT hash is still
//! refused. Approving new things is not the same as approving changes to old
//! ones, and that is exactly the substitution the pin file exists to catch.

use std::path::PathBuf;

use aqua_template_registry::import::ImportStore;
use aqua_template_registry::subscribe::Subscriber;
use aqua_template_registry::trust::{ImportPolicy, PinMode};

struct Args {
    registry: String,
    publisher: String,
    trust: PathBuf,
    store: PathBuf,
    cursor: Option<PathBuf>,
    approve_new: bool,
    once: bool,
    interval: u64,
    list: bool,
    corroborate: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut registry = "http://127.0.0.1:8088".to_string();
    let mut publisher = String::new();
    let mut trust = PathBuf::new();
    let mut store = PathBuf::from("./imported");
    let mut cursor = None;
    let mut approve_new = false;
    let mut once = false;
    let mut interval = 30u64;
    let mut list = false;
    let mut corroborate: Vec<String> = Vec::new();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let mut step = 2;
        let need = |i: usize| -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", argv[i]))
        };
        match argv[i].as_str() {
            "--registry" => registry = need(i)?,
            "--publisher" => publisher = need(i)?,
            "--trust" => trust = PathBuf::from(need(i)?),
            "--store" => store = PathBuf::from(need(i)?),
            "--cursor" => cursor = Some(PathBuf::from(need(i)?)),
            "--interval" => interval = need(i)?.parse().map_err(|e| format!("--interval: {e}"))?,
            "--corroborate" => {
                corroborate = need(i)?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--approve-new" => {
                approve_new = true;
                step = 1;
            }
            "--once" => {
                once = true;
                step = 1;
            }
            "--list" => {
                list = true;
                step = 1;
            }
            "-h" | "--help" => {
                println!(
                    "subscribe --registry URL --publisher DID --trust PATH [--store PATH]\n\
                     [--cursor PATH] [--approve-new] [--once] [--interval SECS] [--list]\n\
                     [--corroborate URL,URL,...]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += step;
    }

    if !list {
        if publisher.is_empty() {
            return Err("--publisher is required".to_string());
        }
        if trust.as_os_str().is_empty() {
            return Err(
                "--trust is required: without a trust policy this would import nothing anyway"
                    .to_string(),
            );
        }
    }

    Ok(Args {
        registry,
        publisher,
        trust,
        store,
        cursor,
        approve_new,
        once,
        interval,
        list,
        corroborate,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let store = ImportStore::open(&args.store)?;

    if args.list {
        // Provenance, when the trust file records any. Shown here because
        // --list is where an operator looks to answer "what am I running and
        // who said I should".
        if !args.trust.as_os_str().is_empty() {
            if let Ok(policy) = ImportPolicy::load(&args.trust) {
                println!(
                    "trust policy {} ({} publisher(s))",
                    args.trust.display(),
                    policy.publisher_count()
                );
                for entry in policy.publishers() {
                    match entry.provenance_summary() {
                        Some(p) => println!("  {}\n      {p}", entry.did),
                        None => println!("  {}\n      (no provenance recorded)", entry.did),
                    }
                }
                if let Some(max_age) = policy.max_head_age_secs() {
                    println!("  feed heads must be no older than {max_age}s");
                }
                println!();
            }
        }

        let records = store.records()?;
        println!(
            "{} imported template(s) in {}",
            records.len(),
            args.store.display()
        );
        for r in records {
            println!("  {}  {}", r.template_hash, r.qualified_name);
            if let Some(d) = &r.display_name {
                println!("      {d}");
            }
            println!("      published by {}", r.publisher_did);
        }
        return Ok(());
    }

    let policy = ImportPolicy::load(&args.trust)?;
    let mode = if args.approve_new {
        PinMode::ApproveNew
    } else {
        PinMode::PinnedOnly
    };

    println!("subscribe");
    println!("  registry  : {}", args.registry);
    println!("  publisher : {}", args.publisher);
    println!(
        "  trust     : {} ({} publisher(s), {} pin(s))",
        args.trust.display(),
        policy.publisher_count(),
        policy.pin_count()
    );
    println!("  store     : {}", args.store.display());
    println!("  mode      : {mode:?}");

    if !policy.allows_publisher(&args.publisher) {
        eprintln!();
        eprintln!("warning: {} is not in allowed_publishers.", args.publisher);
        eprintln!(
            "         Every candidate will be refused. Add the DID to {} first.",
            args.trust.display()
        );
    }

    // ---- corroboration ------------------------------------------------------
    //
    // Run before any sync, and treat a disagreement as fatal. Two mirrors that
    // disagree about a signed root mean one of them is serving something the
    // publisher did not sign at that height, and importing from either without
    // knowing which would be picking a side at random.
    if !args.corroborate.is_empty() {
        let mut urls = vec![args.registry.clone()];
        for u in &args.corroborate {
            if !urls.contains(u) {
                urls.push(u.clone());
            }
        }
        println!("corroborating across {} registries", urls.len());
        let report =
            aqua_template_registry::corroborate::corroborate(&args.publisher, &urls).await?;
        for m in &report.mirrors {
            match (&m.head, &m.error) {
                (Some(h), _) => println!("  {} head {} root {}", m.url, h.head_seq, h.merkle_root),
                (None, Some(e)) => println!("  {} no usable head: {e}", m.url),
                (None, None) => println!("  {} no usable head", m.url),
            }
        }
        for l in &report.lagging {
            println!("  lagging: {} is {} entr(ies) behind", l.url, l.behind);
        }
        for e in &report.equivocations {
            println!(
                "  EQUIVOCATION at height {}: {} says {}, {} says {}",
                e.head_seq, e.url_a, e.root_a, e.url_b, e.root_b
            );
        }
        println!("  {}", report.summary());
        println!();

        if !report.is_consistent() {
            eprintln!("refusing to sync: the mirrors disagree about what this publisher signed.");
            eprintln!("  Resolve this out of band before importing anything. Corroboration cannot");
            eprintln!("  tell you which mirror is honest, and a majority proves nothing if the");
            eprintln!("  mirrors are not independent.");
            std::process::exit(2);
        }
    }

    let cursor_path = args
        .cursor
        .clone()
        .unwrap_or_else(|| args.store.join("cursor.json"));

    let mut subscriber = Subscriber::new(
        &args.registry,
        &args.publisher,
        store,
        policy,
        Some(args.trust.clone()),
        cursor_path,
    )?;

    println!("  cursor    : {}", subscriber.cursor());
    println!();

    loop {
        match subscriber.sync(mode).await {
            Ok(report) => {
                match report.head.as_ref() {
                    Some(aqua_template_registry::subscribe::HeadStatus::Verified(h)) => {
                        println!(
                            "feed head verified: covers {} entries, root {}",
                            h.head_seq, h.merkle_root
                        );
                    }
                    Some(aqua_template_registry::subscribe::HeadStatus::Bootstrapping) => {
                        println!(
                            "no feed head from this publisher yet: withholding and reordering \
                             cannot be detected until they sign one"
                        );
                    }
                    None => {}
                }
                if !report.is_empty() || report.already_present > 0 {
                    println!(
                        "examined {}, imported {}, already present {}, rejected {}, cursor {}",
                        report.examined,
                        report.imported.len(),
                        report.already_present,
                        report.rejected.len(),
                        report.cursor
                    );
                }
                for t in &report.imported {
                    println!("  + {}  {}", t.template_hash, t.qualified_name);
                }
                for name in &report.newly_pinned {
                    println!("  pinned {name} in {}", args.trust.display());
                }
                for r in &report.rejected {
                    println!(
                        "  ! seq {} {} refused: {} ({})",
                        r.seq,
                        r.qualified_name,
                        r.rejection.code(),
                        r.rejection
                    );
                }
                if report.rejected.iter().any(|r| {
                    matches!(
                        r.rejection,
                        aqua_template_registry::import::ImportRejection::NotPinned { .. }
                    )
                }) && !args.approve_new
                {
                    println!(
                        "  (re-run with --approve-new to import and pin the above, \
                         after reviewing the hashes)"
                    );
                }
            }
            Err(e) => {
                // A head failure means the registry's whole view is suspect,
                // so nothing was imported and the cursor did not move. Say so
                // loudly rather than letting it look like a transient blip.
                eprintln!("sync failed [{}]: {e}", e.code());
                if matches!(e, aqua_template_registry::subscribe::SyncError::Head(_)) {
                    eprintln!(
                        "  The publisher's signed feed head does not match what this registry \
                         served."
                    );
                    eprintln!(
                        "  Nothing was imported and the cursor did not advance. Try another \
                         registry or mirror for the same publisher DID."
                    );
                }
                if args.once {
                    return Err(e.into());
                }
            }
        }

        if args.once {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(args.interval)).await;
    }

    Ok(())
}
