//! Build the signed registration trees for the README quickstart.
//!
//! Writes three signed Aqua trees to a directory and prints the `curl` commands
//! that POST them, so the quickstart works with nothing but this example and
//! `curl`. It talks to no network itself.
//!
//! ```text
//! cargo run --example publish -- ./out acme
//! ```
//!
//! Arguments (both optional): output directory (default `./out`) and vendor name
//! (default `acme`). The publisher key is generated fresh on every run, so each
//! run produces a different publisher DID and a different namespace claim.
//!
//! Pass `--seed <0..255>` to derive a deterministic key instead, which is handy
//! when you want to re-run the quickstart against a registry that already has
//! your vendor namespace.

use aqua_rs_sdk_core::Aquafier;
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut positional: Vec<String> = Vec::new();
    let mut seed_byte: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--seed" {
            let v = args
                .get(i + 1)
                .ok_or("--seed needs a value from 0 to 255")?;
            seed_byte = Some(v.parse()?);
            i += 2;
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }

    let out_dir = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "./out".into());
    let vendor = positional.get(1).cloned().unwrap_or_else(|| "acme".into());

    std::fs::create_dir_all(&out_dir)?;

    let key = match seed_byte {
        Some(b) => PublisherKey::from_seed([b; 32])?,
        None => PublisherKey::generate()?,
    };
    let aquafier = Aquafier::new();

    // The hash of whatever template you are publishing. In real use this is the
    // SHA3-256 identity of your own template definition, which you get from
    // aqua-rs-sdk-core: parse it as a `Template`, then `calculate_link`.
    // A placeholder keeps this example self-contained.
    let template_hash = format!("0x{}", "ab".repeat(32));

    // 1. Claim the namespace. Self-certifying: vendor_did is this key's DID.
    let vendor_tree = publisher::vendor_registration(
        &aquafier,
        &key,
        &vendor,
        Some(&format!("{vendor} (quickstart)")),
    )
    .await?;

    // 2. Register a template into it.
    let template_tree = publisher::template_registration(
        &aquafier,
        &key,
        TemplateRegistration {
            vendor: vendor.clone(),
            name: "invoice".into(),
            template_hash: template_hash.clone(),
            supersedes: None,
            display_name: Some("Invoice".into()),
            description: Some("A worked example of a registered template.".into()),
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await?;

    // 3. Give it a short alias.
    let alias_tree =
        publisher::alias_registration(&aquafier, &key, &vendor, "inv", &template_hash).await?;

    for (file, tree) in [
        ("vendor.json", &vendor_tree),
        ("template.json", &template_tree),
        ("alias.json", &alias_tree),
    ] {
        let path = std::path::Path::new(&out_dir).join(file);
        std::fs::write(&path, publisher::to_json_pretty(tree)?)?;
        println!("wrote {}", path.display());
    }

    let did = key.did();
    println!();
    println!("publisher DID : {did}");
    println!("vendor        : {vendor}");
    println!("template hash : {template_hash}");
    println!();
    println!("Submit them (registryd listening on 127.0.0.1:8088):");
    println!();
    println!("  curl -sS -X POST http://127.0.0.1:8088/vendors \\");
    println!("       -H 'content-type: application/json' -d @{out_dir}/vendor.json");
    println!("  curl -sS -X POST http://127.0.0.1:8088/templates \\");
    println!("       -H 'content-type: application/json' -d @{out_dir}/template.json");
    println!("  curl -sS -X POST http://127.0.0.1:8088/aliases \\");
    println!("       -H 'content-type: application/json' -d @{out_dir}/alias.json");
    println!();
    println!("Then read it back:");
    println!();
    println!("  curl -sS http://127.0.0.1:8088/resolve/{vendor}/invoice");
    println!("  curl -sS http://127.0.0.1:8088/publishers/{did}/templates");
    println!("  curl -sS 'http://127.0.0.1:8088/publishers/{did}/feed?since=0'");
    println!();
    println!("Note: the key is not saved. Re-run with --seed <0..255> for a");
    println!("deterministic identity you can publish under twice.");

    Ok(())
}
