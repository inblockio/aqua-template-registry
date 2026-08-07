//! `publish-audit-set`: publish the Aqua audit template family under a vendor
//! namespace, and optionally emit a replayable seed set.
//!
//! This is the registry's first real template set. It registers the eleven
//! audit templates that `aqua-rs-sdk-core` ships (the abstract root
//! `audit_artifact`, the eight per-turn artifact types T1 to T8, and the two
//! closing types `audit_round_anchor` and `audit_session_close`) under the
//! `inblockio` namespace.
//!
//! ```text
//! publish-audit-set [--key PATH] [--data-dir PATH] [--core PATH]
//!                   [--vendor NAME] [--seed-out PATH]
//! ```
//!
//! | Flag | Default | Meaning |
//! |---|---|---|
//! | `--key` | `~/.aqua-registry-publisher/inblockio.key` | Ed25519 seed, hex |
//! | `--data-dir` | `./data` | Registry store to publish into |
//! | `--core` | `../aqua-rs-sdk-core` | Checkout to read templates and the ledger from |
//! | `--vendor` | `inblockio` | Vendor namespace to claim |
//! | `--seed-out` | none | Write the signed trees, definitions, and manifest here |
//!
//! # The key never lives in the repository
//!
//! The publisher key is the whole trust model: whoever holds it owns the
//! namespace. It is therefore kept outside the working tree by default, created
//! with owner-only permissions if it does not exist, and never written to
//! `--seed-out`. The seed set contains only public artifacts: signed trees,
//! template definitions, and a manifest.
//!
//! # Drift is fatal, not a warning
//!
//! Every template hash is recomputed from the definition JSON through core's
//! own `calculate_link` and compared against core's
//! `tests/audit_template_hashes.txt` ledger. A mismatch aborts before anything
//! is signed. Registering a hash that does not match the definition being
//! distributed would publish a name pointing at a type nobody can resolve.

use std::path::{Path, PathBuf};

use aqua_rs_sdk_core::Aquafier;
use aqua_template_registry::feedhead;
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::{templates, Registry};

/// One entry of the audit set: the file stem (which is also the registered
/// name), a display label, and a customer-neutral description.
///
/// The order here is the order of registration, and therefore the order of the
/// feed: the abstract root first, then T1 to T8 in turn order, then the two
/// closing types. A consumer replaying the feed sees the root before anything
/// that derives from it.
const AUDIT_SET: &[(&str, &str, &str)] = &[
    (
        "audit_artifact",
        "Audit artifact",
        "Abstract root of the audit family. Carries the signer DID and creation time common to every audit artifact. Not instantiated directly: the ten derived types terminate their ancestry here.",
    ),
    (
        "audit_user_turn_marker",
        "User turn marker",
        "Opens a turn within an audited session, recording the session, the turn index, and the time the turn opened.",
    ),
    (
        "audit_user_prompt",
        "User prompt",
        "The prompt a user submitted in a turn, with optional hashes of attached files and of an audio recording.",
    ),
    (
        "audit_agent_thinking",
        "Agent reasoning step",
        "A reasoning step the agent produced inside a turn, sequenced within that turn and attributed to a model round.",
    ),
    (
        "audit_agent_tool_call",
        "Agent tool call",
        "A tool invocation the agent requested, with the tool name, its arguments, and an assessed risk level.",
    ),
    (
        "audit_api_response",
        "Attested API response",
        "A response received from an external API during a turn, recording the method, endpoint, status code, request hash, response body, and the attested origin it came from.",
    ),
    (
        "audit_tool_result",
        "Tool result",
        "The outcome of a tool invocation: the result payload, whether it succeeded, and an error message when it did not.",
    ),
    (
        "audit_hitl_approval",
        "Human approval decision",
        "A human-in-the-loop decision on a proposed action, recording what was shown to the approver, the decision taken, and an optional rationale.",
    ),
    (
        "audit_agent_response",
        "Agent response",
        "A response the agent returned to the user within a turn, flagged as final or intermediate.",
    ),
    (
        "audit_round_anchor",
        "Turn round anchor",
        "Closes a turn by committing to its artifacts: the artifact count, the leaf hashes, and their Merkle root.",
    ),
    (
        "audit_session_close",
        "Session close",
        "Closes an audited session, committing to the total turn count, the last turn, the last round anchor, and the reason for closing.",
    ),
];

struct Args {
    head_only: bool,
    key: PathBuf,
    data_dir: PathBuf,
    core: PathBuf,
    vendor: String,
    seed_out: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut args = Args {
        head_only: false,
        key: PathBuf::from(home).join(".aqua-registry-publisher/inblockio.key"),
        data_dir: PathBuf::from("./data"),
        core: PathBuf::from("../aqua-rs-sdk-core"),
        vendor: "inblockio".to_string(),
        seed_out: None,
    };

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
            "--key" => args.key = PathBuf::from(need(i)?),
            "--data-dir" => args.data_dir = PathBuf::from(need(i)?),
            "--core" => args.core = PathBuf::from(need(i)?),
            "--vendor" => args.vendor = need(i)?,
            "--seed-out" => args.seed_out = Some(PathBuf::from(need(i)?)),
            "--head-only" => {
                args.head_only = true;
                step = 1;
            }
            "-h" | "--help" => {
                println!(
                    "publish-audit-set [--key PATH] [--data-dir PATH] [--core PATH]\n\
                     [--vendor NAME] [--seed-out PATH] [--head-only]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += step;
    }
    Ok(args)
}

/// Load the publisher key, creating it with owner-only permissions if absent.
fn load_or_create_key(path: &Path) -> Result<PublisherKey, Box<dyn std::error::Error>> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        let hex_body = text.trim().trim_start_matches("0x");
        let bytes =
            hex::decode(hex_body).map_err(|e| format!("{} is not hex: {e}", path.display()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{} must hold exactly 32 bytes", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "warning: {} is mode {:04o}, group or world readable. \
                     Run: chmod 600 {}",
                    path.display(),
                    mode,
                    path.display()
                );
            }
        }

        let key = PublisherKey::from_seed(seed)?;
        println!("key      : {} (existing)", path.display());
        return Ok(key);
    }

    // Create it. The directory is owner-only too, so a later umask slip on the
    // file is still contained.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let key = PublisherKey::generate()?;
    std::fs::write(path, format!("{}\n", hex::encode(key.seed())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("key      : {} (created, mode 0600)", path.display());
    println!();
    println!("  A new publisher identity was generated. This file is the only");
    println!("  thing that proves ownership of the vendor namespace. Back it up,");
    println!("  and never commit it.");
    println!();
    Ok(key)
}

/// Filename of the signed feed head inside a seed set.
const FEED_HEAD_FILE: &str = "13-feed-head.json";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sign a feed head over an already-published seed set, without touching it.
///
/// Reads the committed manifest for the tips, in the order they were
/// registered, and commits to exactly those. The twelve signed registration
/// trees are read but never rewritten: they are published bytes.
async fn write_head_for_seed(
    seed_dir: &Path,
    key: &PublisherKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = seed_dir.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let mut manifest: serde_json::Value = serde_json::from_str(&text)?;

    let did = manifest["publisher_did"]
        .as_str()
        .ok_or("manifest has no publisher_did")?
        .to_string();
    if did != key.did() {
        return Err(format!(
            "this seed set was published by {did}, but the key at hand is {}",
            key.did()
        )
        .into());
    }

    let registrations = manifest["registrations"]
        .as_array()
        .ok_or("manifest has no registrations")?
        .clone();
    let mut ordered: Vec<(u64, String)> = registrations
        .iter()
        .map(|r| {
            let seq = r["seq"].as_u64().ok_or("registration without seq")?;
            let tip = r["tree_tip"]
                .as_str()
                .ok_or("registration without tree_tip")?
                .to_string();
            Ok::<_, Box<dyn std::error::Error>>((seq, tip))
        })
        .collect::<Result<_, _>>()?;
    ordered.sort_by_key(|(seq, _)| *seq);
    let tips: Vec<String> = ordered.into_iter().map(|(_, tip)| tip).collect();

    let aquafier = Aquafier::new();
    let tree = feedhead::build(&aquafier, &key.credentials(), key.did(), &tips, now_secs()).await?;
    let body = publisher::to_json_pretty(&tree)?;

    // Verify what was just built before writing it, so a broken head never
    // reaches the seed directory.
    let verified = feedhead::verify_head(&aquafier, &body, Some(key.did())).await?;
    feedhead::check_against_entries(&verified, &tips)?;

    std::fs::write(seed_dir.join(FEED_HEAD_FILE), &body)?;

    manifest["feed_head"] = serde_json::json!({
        "file": FEED_HEAD_FILE,
        "head_seq": verified.head_seq,
        "merkle_root": verified.merkle_root,
        "leaf_version": feedhead::LEAF_VERSION,
        "tree_tip": verified.tree_tip,
    });
    std::fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;

    println!("feed head: covers {} entries", verified.head_seq);
    println!("  root     : {}", verified.merkle_root);
    println!("  tree tip : {}", verified.tree_tip);
    println!("  wrote    : {}", seed_dir.join(FEED_HEAD_FILE).display());
    println!("  manifest : {}", manifest_path.display());
    Ok(())
}

/// Parse core's `tests/audit_template_hashes.txt` into (name, bare hash) pairs.
fn read_ledger(core: &Path) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let path = core.join("tests/audit_template_hashes.txt");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read the hash ledger at {}: {e}", path.display()))?;

    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(name), Some(hash)) => out.push((name.to_string(), hash.to_string())),
            _ => return Err(format!("malformed ledger line: {line:?}").into()),
        }
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    println!("publish-audit-set");
    println!("core     : {}", args.core.display());
    println!("data dir : {}", args.data_dir.display());
    println!("vendor   : {}", args.vendor);

    let key = load_or_create_key(&args.key)?;
    println!("publisher: {}", key.did());
    println!();

    // ---- head-only: sign a commitment over an existing seed set ------------
    //
    // Regenerating the whole set to add a head would resign all twelve trees
    // with fresh nonces, replacing bytes that are already published. This path
    // reads the committed manifest instead and commits to exactly those tips.
    if args.head_only {
        let seed_dir = args
            .seed_out
            .clone()
            .ok_or("--head-only needs --seed-out pointing at an existing seed set")?;
        return write_head_for_seed(&seed_dir, &key).await;
    }

    // ---- collect the set, checking every hash against core ------------------
    let ledger = read_ledger(&args.core)?;
    let template_dir = args.core.join("src/schema/templates");

    struct Entry {
        name: &'static str,
        display: &'static str,
        description: &'static str,
        hash: String,
        definition: String,
    }

    let mut entries: Vec<Entry> = Vec::new();
    for (name, display, description) in AUDIT_SET {
        let def_path = template_dir.join(format!("{name}.json"));
        let definition = std::fs::read_to_string(&def_path)
            .map_err(|e| format!("cannot read {}: {e}", def_path.display()))?;

        // Recompute from the definition through core, never trust the ledger alone.
        let computed = templates::template_hash_of_definition(&definition)?;

        let listed = ledger
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| h.clone())
            .ok_or_else(|| format!("{name} is not in core's hash ledger"))?;

        if computed != listed {
            return Err(format!(
                "DRIFT: {name} hashes to {computed} but core's ledger says {listed}. \
                 The ledger and the template definition disagree; refusing to publish."
            )
            .into());
        }

        println!("  {computed}  {name}");
        entries.push(Entry {
            name,
            display,
            description,
            hash: computed,
            definition,
        });
    }
    println!();
    println!("all {} hashes agree with core's ledger", entries.len());
    println!();

    // ---- build, sign, submit ------------------------------------------------
    let registry = Registry::open(&args.data_dir)?;
    let aquafier = Aquafier::new();

    let mut seed_files: Vec<(String, String)> = Vec::new();
    let mut manifest_entries: Vec<serde_json::Value> = Vec::new();

    let vendor_tree = publisher::vendor_registration(
        &aquafier,
        &key,
        &args.vendor,
        Some("inblock.io assets GmbH"),
    )
    .await?;
    let vendor_body = publisher::to_json_pretty(&vendor_tree)?;
    let receipt = registry.submit_vendor(&vendor_body).await?;
    println!(
        "seq {:>2}  vendor    {}",
        receipt.seq, receipt.qualified_name
    );

    let vendor_file = format!("{:02}-vendor-{}.json", receipt.seq, args.vendor);
    manifest_entries.push(serde_json::json!({
        "seq": receipt.seq,
        "kind": "vendor",
        "name": args.vendor,
        "qualified_name": receipt.qualified_name,
        "tree_tip": receipt.tree_tip,
        "tree_file": vendor_file,
    }));
    seed_files.push((vendor_file, vendor_body));

    for entry in &entries {
        let tree = publisher::template_registration(
            &aquafier,
            &key,
            TemplateRegistration {
                vendor: args.vendor.clone(),
                name: entry.name.to_string(),
                template_hash: entry.hash.clone(),
                supersedes: None,
                display_name: Some(entry.display.to_string()),
                description: Some(entry.description.to_string()),
                daemon_trigger: None,
                file_dependency: None,
            },
        )
        .await?;

        let body = publisher::to_json_pretty(&tree)?;
        let receipt = registry.submit_template(&body).await?;

        // Upload the definition body too, so consumers need no out-of-band
        // files. It is accepted purely because it hashes to the hash the
        // registration above just claimed.
        let def = registry.submit_definition(&entry.definition)?;
        debug_assert_eq!(def.template_hash, entry.hash);

        println!(
            "seq {:>2}  template  {}",
            receipt.seq, receipt.qualified_name
        );

        let tree_file = format!("{:02}-template-{}.json", receipt.seq, entry.name);
        manifest_entries.push(serde_json::json!({
            "seq": receipt.seq,
            "kind": "template",
            "name": entry.name,
            "qualified_name": receipt.qualified_name,
            "template_hash": entry.hash,
            "display_name": entry.display,
            "tree_tip": receipt.tree_tip,
            "tree_file": tree_file,
            "definition_file": format!("definitions/{}.json", entry.name),
        }));
        seed_files.push((tree_file, body));
    }

    // ---- sign a feed head over everything just published -------------------
    //
    // Without this the registry could serve a subscriber a truncated view of
    // the set and nothing would notice. The head is built over the publisher's
    // own entries in feed order, which is exactly what the registry returns.
    let tips = registry.publisher_entry_tips(key.did());
    let head_tree =
        feedhead::build(&aquafier, &key.credentials(), key.did(), &tips, now_secs()).await?;
    let head_body = publisher::to_json_pretty(&head_tree)?;
    let head_receipt = registry.submit_head(&head_body).await?;
    println!();
    println!(
        "feed head: covers {} entries, root {}",
        head_receipt.head_seq, head_receipt.merkle_root
    );

    let stats = registry.stats();
    println!();
    println!(
        "registry : seq={} vendors={} templates={} publishers={}",
        stats.head_seq, stats.vendors, stats.templates, stats.publishers
    );

    // ---- optional seed set --------------------------------------------------
    if let Some(seed_dir) = &args.seed_out {
        std::fs::create_dir_all(seed_dir)?;
        let def_dir = seed_dir.join("definitions");
        std::fs::create_dir_all(&def_dir)?;

        for (file, body) in &seed_files {
            std::fs::write(seed_dir.join(file), body)?;
        }
        // The definitions are the distributable template bodies. Written byte
        // for byte from core: their hash is their identity.
        for entry in &entries {
            std::fs::write(
                def_dir.join(format!("{}.json", entry.name)),
                &entry.definition,
            )?;
        }

        let core_tip = std::process::Command::new("git")
            .args([
                "-C",
                &args.core.display().to_string(),
                "rev-parse",
                "--short",
                "HEAD",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        std::fs::write(seed_dir.join(FEED_HEAD_FILE), &head_body)?;

        let manifest = serde_json::json!({
            "set": "audit-set-v1",
            "vendor": args.vendor,
            "publisher_did": key.did(),
            "registration_count": manifest_entries.len(),
            "source": {
                "repo": "aqua-rs-sdk-core",
                "tip": core_tip,
                "ledger": "tests/audit_template_hashes.txt",
                "definitions": "src/schema/templates",
            },
            "registrations": manifest_entries,
            "feed_head": {
                "file": FEED_HEAD_FILE,
                "head_seq": head_receipt.head_seq,
                "merkle_root": head_receipt.merkle_root,
                "leaf_version": aqua_template_registry::feedhead::LEAF_VERSION,
                "tree_tip": head_receipt.tree_tip,
            },
        });
        std::fs::write(
            seed_dir.join("manifest.json"),
            format!("{}\n", serde_json::to_string_pretty(&manifest)?),
        )?;

        println!();
        println!(
            "seed set : {} ({} trees, {} definitions, manifest.json)",
            seed_dir.display(),
            seed_files.len(),
            entries.len()
        );
        println!("           the private key is NOT part of the seed set");
    }

    Ok(())
}
