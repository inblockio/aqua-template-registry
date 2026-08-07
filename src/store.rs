//! Durable, on-disk storage for the registry's append-only feed.
//!
//! The durable state of this registry is a single append-only log of accepted
//! registrations (`FeedEntry`) plus the full signed Aqua tree behind each one.
//! Everything else the registry serves (vendor ownership, template lineage,
//! alias resolution, ...) is a derived index that gets rebuilt by replaying
//! that log at startup. Because the log is small, append-only, and read in
//! full exactly once per process lifetime, an embedded database buys nothing
//! here: no query planner is needed, no concurrent-writer story is needed,
//! and no schema migration story is needed. What is actually wanted is:
//!
//! - a format an operator can `cat` and grep without tooling,
//! - a format that survives a crash mid-write without corrupting anything
//!   else in the store,
//! - a format that is trivial to back up (`cp -r`, `rsync`, `tar`), and
//! - zero extra dependencies.
//!
//! Plain JSON files, one per entry, satisfy all four. This module is the
//! only place in the crate that touches the filesystem.
//!
//! # On-disk layout
//!
//! ```text
//! <root>/
//!   entries/000000000001.json      # one FeedEntry per file
//!   entries/000000000002.json
//!   trees/<tree_tip>.json          # the full signed Aqua tree, verbatim
//! ```
//!
//! Entry filenames are the `seq` number, zero-padded to 12 digits. Padding
//! every filename to the same width makes plain lexicographic order (what
//! every directory listing, `ls`, and `std::fs::read_dir` gives you for free)
//! equal to numeric order, so `load_all` never has to parse a filename to
//! figure out iteration order; sorting the parsed `seq` field is enough, and
//! even an operator eyeballing `ls entries/` sees entries in creation order.
//! Twelve digits supports sequence numbers up to 999,999,999,999, which is
//! far beyond anything this registry will accumulate in its lifetime.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::{RegistryError, Result};
use crate::model::FeedEntry;

/// A durable, file-backed store for the registry's append-only feed.
///
/// One `Store` owns one root directory on disk. All state (the feed of
/// accepted registrations, and the full signed trees behind them) lives
/// under that root; nothing is cached in memory across calls, so a `Store`
/// is cheap to construct and safe to open more than once against the same
/// root (the derived in-memory index lives one layer up, not here).
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens a store rooted at `root`, creating the root and its two
    /// subdirectories (`entries/`, `trees/`) if they do not already exist.
    ///
    /// Safe to call against an existing store; this never truncates or
    /// otherwise touches files that are already there.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| storage_err(&root, e))?;
        let store = Store { root };
        fs::create_dir_all(store.entries_dir())
            .map_err(|e| storage_err(&store.entries_dir(), e))?;
        fs::create_dir_all(store.trees_dir()).map_err(|e| storage_err(&store.trees_dir(), e))?;
        fs::create_dir_all(store.definitions_dir())
            .map_err(|e| storage_err(&store.definitions_dir(), e))?;
        fs::create_dir_all(store.heads_dir()).map_err(|e| storage_err(&store.heads_dir(), e))?;
        Ok(store)
    }

    /// The root directory this store was opened with.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `entries/` subdirectory, one `FeedEntry` JSON file per registered
    /// `seq`.
    fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    /// The `trees/` subdirectory, one signed-tree JSON file per `tree_tip`.
    fn trees_dir(&self) -> PathBuf {
        self.root.join("trees")
    }

    /// The `definitions/` subdirectory, one template definition body per bare
    /// template hash.
    ///
    /// Definition bodies are content addressed: the filename IS the hash of
    /// the contents. Nothing else about them needs to be trusted, which is
    /// why they are stored separately from the signed registration trees
    /// rather than inside them.
    fn definitions_dir(&self) -> PathBuf {
        self.root.join("definitions")
    }

    /// The `heads/` subdirectory, one directory per publisher DID holding that
    /// publisher's signed feed heads, one file per `head_seq`.
    ///
    /// Heads are kept out of `entries/` deliberately. A head commits to feed
    /// entries, so filing it as one would either make it commit to itself or
    /// leave a hole in the numbering.
    fn heads_dir(&self) -> PathBuf {
        self.root.join("heads")
    }

    /// A publisher's head directory.
    ///
    /// The DID is hex encoded rather than sanitised. A DID contains `:` and can
    /// in principle contain anything else, and any lossy mapping (replacing bad
    /// characters, truncating) risks two DIDs colliding onto one directory,
    /// which would let one publisher's heads answer for another's. Hex is
    /// unambiguous, reversible, and safe on every filesystem.
    fn head_dir_for(&self, publisher_did: &str) -> PathBuf {
        self.heads_dir().join(hex::encode(publisher_did.as_bytes()))
    }

    /// Store a signed feed head tree for a publisher at a given height.
    pub fn write_head(&self, publisher_did: &str, head_seq: u64, tree_json: &str) -> Result<()> {
        let dir = self.head_dir_for(publisher_did);
        fs::create_dir_all(&dir).map_err(|e| storage_err(&dir, e))?;
        write_atomically(&dir.join(entry_filename(head_seq)), tree_json.as_bytes())
    }

    /// A publisher's head at a given height, verbatim.
    pub fn read_head(&self, publisher_did: &str, head_seq: u64) -> Result<Option<String>> {
        let path = self
            .head_dir_for(publisher_did)
            .join(entry_filename(head_seq));
        match fs::read_to_string(&path) {
            Ok(c) => Ok(Some(c)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage_err(&path, e)),
        }
    }

    /// Every height at which this publisher has a stored head, ascending.
    pub fn head_seqs(&self, publisher_did: &str) -> Result<Vec<u64>> {
        let dir = self.head_dir_for(publisher_did);
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(storage_err(&dir, e)),
        };
        let mut out = Vec::new();
        for item in rd {
            let item = item.map_err(|e| storage_err(&dir, e))?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(seq) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                out.push(seq);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// The publisher's highest stored head, verbatim, with its height.
    pub fn read_latest_head(&self, publisher_did: &str) -> Result<Option<(u64, String)>> {
        let Some(top) = self.head_seqs(publisher_did)?.pop() else {
            return Ok(None);
        };
        Ok(self.read_head(publisher_did, top)?.map(|tree| (top, tree)))
    }

    /// Replays every persisted entry in ascending `seq` order.
    ///
    /// Intended to be called once at startup to rebuild the in-memory index;
    /// nothing in this module keeps that index, so it is the caller's job to
    /// fold the returned entries into whatever indices it maintains.
    ///
    /// A missing or empty `entries/` directory is not an error: a brand new
    /// store has nothing to replay, so this returns an empty `Vec`.
    ///
    /// Every file whose name ends in `.json` is parsed as a `FeedEntry`; a
    /// file that fails to parse is reported as [`RegistryError::CorruptStore`]
    /// rather than skipped, because a silently skipped file is a silently
    /// lost registration and this store must never lose one quietly. Files
    /// not ending in `.json` (in particular, `*.json.tmp` leftovers from an
    /// interrupted [`Store::append`]) are ignored: they were never the
    /// commit point of a write, so they carry no information.
    ///
    /// After parsing, the `seq` values are checked to be exactly `1..=n`
    /// with no gaps and no duplicates. A gap means a registration is
    /// missing from disk; that is corruption, not an empty slot, so it is
    /// reported as [`RegistryError::CorruptStore`] rather than silently
    /// renumbered or skipped.
    pub fn load_all(&self) -> Result<Vec<FeedEntry>> {
        let dir = self.entries_dir();
        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(storage_err(&dir, e)),
        };

        let mut entries = Vec::new();
        for item in read_dir {
            let item = item.map_err(|e| storage_err(&dir, e))?;
            let path = item.path();

            let is_file = item
                .file_type()
                .map_err(|e| storage_err(&path, e))?
                .is_file();
            if !is_file || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                // Skips directories, `*.json.tmp` (its extension is "tmp",
                // not "json"), and anything else that is not a committed
                // entry file.
                continue;
            }

            let bytes = fs::read(&path).map_err(|e| storage_err(&path, e))?;
            let entry: FeedEntry =
                serde_json::from_slice(&bytes).map_err(|e| RegistryError::CorruptStore {
                    path: path.display().to_string(),
                    reason: format!("failed to parse entry as FeedEntry: {e}"),
                })?;
            entries.push(entry);
        }

        entries.sort_by_key(|entry| entry.seq);

        for (index, entry) in entries.iter().enumerate() {
            let expected = (index + 1) as u64;
            if entry.seq != expected {
                return Err(RegistryError::CorruptStore {
                    path: dir.display().to_string(),
                    reason: format!(
                        "sequence gap or duplicate: expected next seq to be {expected}, found {}",
                        entry.seq
                    ),
                });
            }
        }

        Ok(entries)
    }

    /// Durably appends one accepted registration.
    ///
    /// Writes the tree blob first, then the entry file, each atomically
    /// (see `write_atomically`). The entry file is the commit point of an
    /// append: once it exists on disk, every reader can rely on its
    /// `tree_tip` already having a tree blob on disk too, because that blob
    /// was written first and `write_atomically` never leaves a partial file
    /// behind. Writing in the opposite order would let a crash between the
    /// two writes produce an entry that points at a tree nobody ever
    /// persisted, an unrecoverable gap. With this order, the only possible
    /// crash artifact is a tree blob with no entry referencing it yet; that
    /// is harmless, inert garbage (it is simply overwritten if the same
    /// `tree_tip` is appended again, and otherwise ignored forever), so this
    /// method makes no attempt to detect or clean it up.
    ///
    /// Returns an error, and leaves no half-written entry behind, if:
    /// - `entry.tree_tip` is not a valid tip hash (see `tree_filename`);
    ///   reported as [`RegistryError::Storage`] with an
    ///   [`io::ErrorKind::InvalidInput`] source, since this is a caller
    ///   input problem rather than an I/O failure or existing corruption,
    /// - an entry for `entry.seq` already exists; reported as
    ///   [`RegistryError::Storage`] with an [`io::ErrorKind::AlreadyExists`]
    ///   source. Registrations are immutable once accepted, so overwriting
    ///   an existing `seq` is always a bug in the caller, never a legitimate
    ///   update.
    pub fn append(&self, entry: &FeedEntry, tree_json: &str) -> Result<()> {
        let tree_name = tree_filename(&entry.tree_tip).map_err(|_| RegistryError::Storage {
            path: entry.tree_tip.clone(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "tree_tip must be `0x` followed by 1..=256 hex digits",
            ),
        })?;

        let entry_path = self.entries_dir().join(entry_filename(entry.seq));
        if entry_path.exists() {
            return Err(RegistryError::Storage {
                path: entry_path.display().to_string(),
                source: io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("an entry for seq {} already exists", entry.seq),
                ),
            });
        }

        // Tree blob first (see doc comment above for why this order matters).
        // Written verbatim, not re-serialized: `tree_json` is the exact bytes
        // the publisher signed, and round-tripping it through serde_json
        // could reorder object keys, which would make the stored blob no
        // longer byte-identical to what was actually signed.
        let tree_path = self.trees_dir().join(tree_name);
        write_atomically(&tree_path, tree_json.as_bytes())?;

        // FeedEntry has no maps and no floats, so serializing it cannot fail
        // in practice; there is no meaningful error to report if it somehow
        // did, since it would indicate a bug in this crate, not bad input or
        // bad disk state.
        let entry_json =
            serde_json::to_string_pretty(entry).expect("FeedEntry serialization is infallible");
        write_atomically(&entry_path, entry_json.as_bytes())?;

        Ok(())
    }

    /// Fetches the stored signed tree for `tree_tip`, verbatim, or `None` if
    /// no tree has been stored under that tip.
    ///
    /// `tree_tip` is validated the same way as in [`Store::append`] (see
    /// `tree_filename`), but since callers are expected to pass a
    /// `tree_tip` taken from a persisted `FeedEntry`, a value that fails
    /// validation here is reported as [`RegistryError::CorruptStore`] rather
    /// than a plain input error: it means the string this method was asked
    /// to resolve to a path could not have come from a valid entry, whether
    /// because it was tampered with, mistyped, or invented outright.
    pub fn read_tree(&self, tree_tip: &str) -> Result<Option<String>> {
        let tree_name = tree_filename(tree_tip)?;
        let path = self.trees_dir().join(tree_name);
        match fs::read_to_string(&path) {
            Ok(contents) => Ok(Some(contents)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage_err(&path, e)),
        }
    }

    /// Store a template definition body under its bare hash.
    ///
    /// The caller is responsible for having recomputed that hash from the body
    /// itself; this only guards the filename. Writing is idempotent by
    /// construction: the same body always lands on the same path with the same
    /// contents, so a repeat upload is a no-op rather than a conflict.
    pub fn write_definition(&self, template_hash: &str, body: &str) -> Result<()> {
        let name = definition_filename(template_hash)?;
        write_atomically(&self.definitions_dir().join(name), body.as_bytes())
    }

    /// Read a stored definition body verbatim. `None` when it was never
    /// uploaded.
    ///
    /// Returned exactly as written, because the whole point of a
    /// content-addressed body is that the reader can hash it and check. A
    /// re-serialization here would reorder keys and break that check.
    pub fn read_definition(&self, template_hash: &str) -> Result<Option<String>> {
        let name = definition_filename(template_hash)?;
        let path = self.definitions_dir().join(name);
        match fs::read_to_string(&path) {
            Ok(contents) => Ok(Some(contents)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage_err(&path, e)),
        }
    }

    /// Every template hash that has a stored definition body.
    pub fn definition_hashes(&self) -> Result<Vec<String>> {
        let dir = self.definitions_dir();
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(storage_err(&dir, e)),
        };
        let mut out = Vec::new();
        for item in read_dir {
            let item = item.map_err(|e| storage_err(&dir, e))?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// The highest `seq` present on disk, or 0 when the store is empty.
    ///
    /// Deliberately does not parse any file's contents: it lists
    /// `entries/`, keeps only names ending in `.json` (so `*.json.tmp`
    /// leftovers are ignored, same as [`Store::load_all`]), and takes the
    /// numeric maximum of the remaining filenames. Because those filenames
    /// are zero-padded (see the module doc comment), the numeric maximum and
    /// the lexicographic maximum agree; either would work, and parsing to
    /// `u64` is used here since it does not depend on the padding width
    /// being exactly right.
    pub fn head_seq(&self) -> Result<u64> {
        let dir = self.entries_dir();
        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(storage_err(&dir, e)),
        };

        let mut max_seq: u64 = 0;
        for item in read_dir {
            let item = item.map_err(|e| storage_err(&dir, e))?;
            let path = item.path();

            let is_file = item
                .file_type()
                .map_err(|e| storage_err(&path, e))?
                .is_file();
            if !is_file || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            if let Some(seq) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
            {
                max_seq = max_seq.max(seq);
            }
            // A `.json` file whose stem is not a plain number is not one of
            // ours; head_seq only cares about the highest valid seq, so such
            // a file is simply not counted rather than treated as an error
            // (load_all is the method responsible for full validation).
        }

        Ok(max_seq)
    }
}

/// Writes `contents` to `path` atomically.
///
/// The write goes to a sibling file named `<path>.tmp` in the same
/// directory, which is `sync_all()`ed to force it to durable storage, and
/// only then `rename`d onto `path`. A rename within the same filesystem is
/// atomic: at every instant, a reader either sees the old contents of
/// `path` (if it existed) or the complete new contents, never a
/// partially-written mix, and never a state where `path` is briefly missing.
/// A crash at any point before the rename leaves `path` untouched and only
/// an inert, ignorable `.tmp` file behind; a crash during or after the
/// rename leaves `path` fully written. This is why the tmp file must live
/// in the same directory as the final path: renames are only guaranteed
/// atomic when source and destination are on the same filesystem, and
/// same-directory is the simplest way to guarantee that.
fn write_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);

    let mut file = fs::File::create(&tmp_path).map_err(|e| storage_err(&tmp_path, e))?;
    file.write_all(contents)
        .map_err(|e| storage_err(&tmp_path, e))?;
    file.sync_all().map_err(|e| storage_err(&tmp_path, e))?;
    drop(file);

    fs::rename(&tmp_path, path).map_err(|e| storage_err(path, e))?;
    Ok(())
}

/// Validates `tree_tip` and turns it into a filename for `trees/`.
///
/// `tree_tip` is used verbatim as a filename, so without validation a
/// caller could pass something like `"../../etc/passwd"` or a value
/// containing `/` and reach outside the `trees/` directory entirely: a
/// classic path-traversal hole. This function is the single choke point
/// that both [`Store::append`] and [`Store::read_tree`] go through before
/// touching the filesystem, so the guard cannot be bypassed by adding a new
/// call site later.
///
/// A valid `tree_tip` is exactly `0x` followed by 1 to 256 ASCII hex digits
/// (either case), which is the shape the tree hashing scheme actually
/// produces; anything else is rejected.
fn tree_filename(tree_tip: &str) -> Result<String> {
    if is_valid_tree_tip(tree_tip) {
        Ok(format!("{tree_tip}.json"))
    } else {
        Err(RegistryError::CorruptStore {
            path: tree_tip.to_string(),
            reason: "tree_tip must be `0x` followed by 1..=256 hex digits".to_string(),
        })
    }
}

/// Validates a bare template hash and turns it into a filename for
/// `definitions/`.
///
/// Same path-traversal choke point as `tree_filename`, but stricter: a bare
/// template hash is always exactly `0x` plus 64 hex digits (a SHA3-256 digest),
/// so anything else is refused rather than merely length-capped.
fn definition_filename(template_hash: &str) -> Result<String> {
    let ok = template_hash
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(format!("{}.json", template_hash.to_ascii_lowercase()))
    } else {
        Err(RegistryError::InvalidHash {
            field: "template_hash",
            reason: "must be `0x` followed by exactly 64 hex digits".to_string(),
        })
    }
}

/// True if `tip` is `0x` followed by 1 to 256 ASCII hex digits.
fn is_valid_tree_tip(tip: &str) -> bool {
    match tip.strip_prefix("0x") {
        Some(hex) => {
            !hex.is_empty() && hex.len() <= 256 && hex.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// The filename for a given `seq`: zero-padded to 12 digits, plus `.json`.
/// See the module doc comment for why the padding matters.
fn entry_filename(seq: u64) -> String {
    format!("{seq:012}.json")
}

/// Wraps an I/O error with the path it happened on.
fn storage_err(path: &Path, source: io::Error) -> RegistryError {
    RegistryError::Storage {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::model::{RegistrationKind, RegistrationPayload, VendorRegistration};

    /// A unique, self-cleaning directory under the OS temp dir for a single
    /// test to use as a store root.
    ///
    /// Uniqueness comes from the current process id plus a per-process
    /// atomic counter, so parallel test threads (and parallel test binaries)
    /// never collide on the same path. Deliberately hand-rolled rather than
    /// pulling in the `tempfile` crate, per this module's own no-extra-deps
    /// rule.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aqua-template-registry-store-test-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).expect("create temp dir for test");
            TempDir { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best-effort: if a test already removed things, or a prior
            // assertion failure left something odd behind, do not panic
            // inside a Drop over it.
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Builds a `FeedEntry` using the crate's real model types, so these
    /// tests fail to compile (rather than silently drift) if the model
    /// shape ever changes.
    fn sample_entry(seq: u64, tree_tip: &str) -> FeedEntry {
        FeedEntry {
            seq,
            kind: RegistrationKind::Vendor,
            publisher_did: "did:key:z6MkTestPublisher".to_string(),
            tree_tip: tree_tip.to_string(),
            received_at: 1_700_000_000,
            qualified_name: "acme".to_string(),
            payload: RegistrationPayload::Vendor(VendorRegistration {
                vendor_name: "acme".to_string(),
                display_name: Some("Acme Corp".to_string()),
                vendor_did: "did:key:z6MkTestPublisher".to_string(),
            }),
        }
    }

    #[test]
    fn open_creates_directories_and_starts_empty() {
        let dir = TempDir::new();
        let root = dir.path().join("store");
        let store = Store::open(&root).expect("open");

        assert!(root.join("entries").is_dir());
        assert!(root.join("trees").is_dir());
        assert_eq!(store.root(), root.as_path());
        assert_eq!(store.head_seq().expect("head_seq"), 0);
        assert!(store.load_all().expect("load_all").is_empty());
    }

    #[test]
    fn append_then_load_all_round_trips_entry() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        let entry = sample_entry(1, "0xabc123");
        store.append(&entry, "{\"tree\":true}").expect("append");

        let loaded = store.load_all().expect("load_all");
        assert_eq!(loaded, vec![entry]);
    }

    #[test]
    fn read_tree_returns_bytes_verbatim() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        let entry = sample_entry(1, "0xDEADbeef01");
        // Unusual key order (not alphabetical) plus trailing whitespace:
        // read_tree must not normalize either away.
        let tree_json = "{\"zebra\":1,\"apple\":2,\"middle\":3}   \n";
        store.append(&entry, tree_json).expect("append");

        let read_back = store
            .read_tree("0xDEADbeef01")
            .expect("read_tree")
            .expect("tree should be present");
        assert_eq!(read_back, tree_json);
    }

    #[test]
    fn read_tree_unknown_tip_returns_none() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        let result = store
            .read_tree("0x1234")
            .expect("read_tree should not error");
        assert_eq!(result, None);
    }

    #[test]
    fn append_same_seq_twice_errors() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        store
            .append(&sample_entry(1, "0xaaaa"), "{}")
            .expect("first append");

        let err = store
            .append(&sample_entry(1, "0xbbbb"), "{}")
            .expect_err("second append with the same seq must fail");
        assert!(matches!(err, RegistryError::Storage { .. }));

        // The first entry must survive untouched.
        let loaded = store.load_all().expect("load_all");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].tree_tip, "0xaaaa");
    }

    #[test]
    fn head_seq_after_three_appends_is_three() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        store
            .append(&sample_entry(1, "0x01"), "{}")
            .expect("append 1");
        store
            .append(&sample_entry(2, "0x02"), "{}")
            .expect("append 2");
        store
            .append(&sample_entry(3, "0x03"), "{}")
            .expect("append 3");

        assert_eq!(store.head_seq().expect("head_seq"), 3);
    }

    #[test]
    fn load_all_detects_seq_gap() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        store
            .append(&sample_entry(1, "0x01"), "{}")
            .expect("append 1");
        // Skip seq 2 entirely.
        store
            .append(&sample_entry(3, "0x03"), "{}")
            .expect("append 3");

        let err = store.load_all().expect_err("a seq gap must be detected");
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_all_detects_corrupt_entry_file() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        store
            .append(&sample_entry(1, "0x01"), "{}")
            .expect("append 1");

        let bad_path = dir.path().join("entries").join("000000000002.json");
        fs::write(&bad_path, b"this is not json").expect("write corrupt entry file");

        let err = store
            .load_all()
            .expect_err("a corrupt entry file must be reported, not skipped");
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn append_rejects_path_traversal_tree_tip() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");

        let err = store
            .append(&sample_entry(1, "0x../../etc/passwd"), "{}")
            .expect_err("must reject a tree_tip with path-traversal segments");
        assert!(matches!(err, RegistryError::Storage { .. }));

        let err = store
            .append(&sample_entry(1, "../escape"), "{}")
            .expect_err("must reject a tree_tip missing the 0x prefix entirely");
        assert!(matches!(err, RegistryError::Storage { .. }));

        // Neither rejected append should have written anything.
        assert_eq!(store.head_seq().expect("head_seq"), 0);
        assert!(store.load_all().expect("load_all").is_empty());
    }

    #[test]
    fn read_tree_rejects_path_traversal_tip() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");

        let err = store
            .read_tree("0x../../etc/passwd")
            .expect_err("must reject a tip with path-traversal segments");
        assert!(matches!(err, RegistryError::CorruptStore { .. }));

        let err = store
            .read_tree("../escape")
            .expect_err("must reject a tip missing the 0x prefix entirely");
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_all_ignores_tmp_files() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");
        store
            .append(&sample_entry(1, "0x01"), "{}")
            .expect("append 1");

        let tmp_path = dir.path().join("entries").join("000000000002.json.tmp");
        fs::write(&tmp_path, b"{ not valid json, and also a .tmp leftover")
            .expect("write tmp file");

        let loaded = store.load_all().expect("load_all should ignore .tmp files");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            store
                .head_seq()
                .expect("head_seq should ignore .tmp files too"),
            1
        );
    }
}
