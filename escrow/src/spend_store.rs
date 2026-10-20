//! Persistence for pending offchain spends.
//!
//! An Arkade offchain spend is two server calls, `submit` then `finalize`.
//! Once the server has accepted `submit` it locks the inputs until the spend
//! is finalized, so a crash or lost response anywhere after the request left
//! the process must be recoverable from local state. A retry that resubmits
//! a *new* transaction for the same inputs fails with "inputs already locked".
//!
//! [`EscrowClient::spend_escrow_offchain`](crate::client::EscrowClient::spend_escrow_offchain)
//! therefore records a [`PendingSpend`] *before* the first request leaves the
//! process, upgrades it once the server's verified ark tx co-signature and
//! checkpoint signatures are in hand, and marks it [`SpendStage::Finalized`]
//! after `finalize` succeeds. Finalized records are kept, not removed: they
//! are the parties' evidence of the server's commitment.
//!
//! [`SpendStore`] is the trait that backends implement. A file-based default
//! ([`FileSpendStore`]) is provided.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoin::Psbt;
use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::hashes::{Hash, sha256};
use rand::RngCore;

/// How far an offchain spend had progressed when its record was last written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendStage {
    /// The record was written before `submit` was sent. The server may or may
    /// not have accepted the transaction. Resuming re-sends the same `submit`.
    Submitting,
    /// `submit` succeeded and the fully-signed checkpoints are stored.
    /// Resuming re-sends `finalize`.
    Submitted,
    /// `finalize` succeeded. The record is kept: it holds the server's
    /// verified co-signature on the ark tx and the fully-signed checkpoints,
    /// the parties' only evidence of the server's commitment. Resuming
    /// returns the ark txid without contacting the server. Removal is up to
    /// the application's retention policy ([`SpendStore::remove`]).
    Finalized,
}

impl Default for SpendStage {
    /// Records written before the stage existed were only ever saved after a
    /// successful `submit`.
    fn default() -> Self {
        Self::Submitted
    }
}

/// State persisted across the submit/finalize round-trips.
///
/// A record is written at [`SpendStage::Submitting`] with everything needed
/// to re-send `submit`, and rewritten at [`SpendStage::Submitted`] with the
/// fully-signed checkpoints (all party + server signatures merged) needed to
/// re-send `finalize`.
///
/// Fields added after the first release carry serde defaults so records
/// written by older versions still load (as [`SpendStage::Submitted`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingSpend {
    /// Application-level identifier (e.g. trade ID).
    pub id: String,
    /// The Arkade transaction ID (hex). Computed locally from the ark tx, so
    /// it is known before `submit`.
    pub ark_txid: String,
    /// Fully-signed checkpoint PSBTs (base64-encoded), ready for finalize.
    /// Empty while [`SpendStage::Submitting`].
    pub signed_checkpoints: Vec<String>,
    /// Progress marker. See [`SpendStage`].
    #[serde(default)]
    pub stage: SpendStage,
    /// Random token identifying the attempt that wrote this record. Passed to
    /// [`SpendStore::remove_if`] so a finished attempt never deletes a record
    /// written by a concurrent one. Empty for records written by older
    /// versions.
    #[serde(default)]
    pub token: String,
    /// The ark tx PSBT (base64) with all party signatures merged, as sent to
    /// `submit`. Present while [`SpendStage::Submitting`].
    #[serde(default)]
    pub ark_tx: Option<String>,
    /// Unsigned checkpoint PSBTs (base64) as sent to `submit`. Present while
    /// [`SpendStage::Submitting`].
    #[serde(default)]
    pub unsigned_checkpoints: Vec<String>,
    /// Each party's signed checkpoint PSBTs (base64). Outer: one entry per
    /// party. Inner: one PSBT per checkpoint. Present while
    /// [`SpendStage::Submitting`].
    #[serde(default)]
    pub party_signed_checkpoints: Vec<Vec<String>>,
    /// The ark tx PSBT (base64) as co-signed by the server, verified. Present
    /// from [`SpendStage::Submitted`] on. Kept so the parties hold the
    /// server's commitment to the payout independently of `finalize`.
    #[serde(default)]
    pub server_signed_ark_tx: Option<String>,
}

impl PendingSpend {
    /// Generate a fresh attempt token.
    pub fn new_token() -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            write!(hex, "{byte:02x}").expect("hex write");
        }
        hex
    }
}

/// Trait for persisting pending spends.
///
/// Implementations must make `save` durable before returning: once it
/// returns, the record must survive a process crash. The spend protocol
/// sends `submit` only after `save` has returned.
pub trait SpendStore {
    /// Persist a pending spend. Overwrites any existing entry for the same ID.
    fn save(&self, spend: &PendingSpend) -> Result<()>;

    /// Load a pending spend by its application-level ID.
    fn load(&self, id: &str) -> Result<Option<PendingSpend>>;

    /// Remove a spend record unconditionally.
    ///
    /// The spend protocol calls this only to clear a record the server
    /// definitively rejected (via [`remove_if`]). Finalized records are left
    /// for the application to prune under its own retention policy.
    ///
    /// [`remove_if`]: SpendStore::remove_if
    fn remove(&self, id: &str) -> Result<()>;

    /// Remove the pending spend for `id` only if its stored token equals
    /// `token`. Returns whether a record was removed.
    ///
    /// A record with an empty token (written by an older version) matches any
    /// `token`.
    ///
    /// The default implementation is load → compare → [`remove`], which is
    /// not atomic: a record replaced between the load and the remove is
    /// still deleted. It is only safe under the documented rule that spends
    /// for one `id` never run concurrently. Backends that can
    /// compare-and-delete in one step (e.g. `DELETE ... WHERE id = ? AND
    /// token = ?`) should override it to get a real guarantee.
    ///
    /// [`remove`]: SpendStore::remove
    fn remove_if(&self, id: &str, token: &str) -> Result<bool> {
        match self.load(id)? {
            Some(existing) if existing.token.is_empty() || existing.token == token => {
                self.remove(id)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// File-based [`SpendStore`]: one JSON file per pending spend in a directory.
///
/// `save` fsyncs the file and its directory before returning.
pub struct FileSpendStore {
    dir: PathBuf,
}

impl FileSpendStore {
    /// Create a new file-based store. The directory is created if it doesn't
    /// exist.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating spend store directory: {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path_for(&self, id: &str) -> PathBuf {
        // Hash the ID to get a fixed-length, collision-free, path-safe filename.
        let hash = sha256::Hash::hash(id.as_bytes());
        let mut hex = String::with_capacity(64);
        for byte in AsRef::<[u8]>::as_ref(&hash) {
            write!(hex, "{byte:02x}").expect("hex write");
        }
        self.dir.join(format!("{hex}.json"))
    }

    fn sync_dir(&self) -> Result<()> {
        // Directory fsync makes the rename durable. `save` must not report
        // success unless this succeeded.
        #[cfg(unix)]
        {
            std::fs::File::open(&self.dir)
                .with_context(|| format!("opening {} for sync", self.dir.display()))?
                .sync_all()
                .with_context(|| format!("syncing {}", self.dir.display()))?;
        }
        Ok(())
    }
}

impl SpendStore for FileSpendStore {
    fn save(&self, spend: &PendingSpend) -> Result<()> {
        let path = self.path_for(&spend.id);
        let json = serde_json::to_string_pretty(spend).context("serializing pending spend")?;

        // Write to a temp file, fsync it, rename over the target, fsync the
        // directory. The record is durable when this returns.
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            file.write_all(json.as_bytes())
                .with_context(|| format!("writing {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing {}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
        self.sync_dir()?;

        Ok(())
    }

    fn load(&self, id: &str) -> Result<Option<PendingSpend>> {
        let path = self.path_for(id);
        match std::fs::read_to_string(&path) {
            Ok(json) => {
                let spend: PendingSpend = serde_json::from_str(&json)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(spend))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn remove(&self, id: &str) -> Result<()> {
        let path = self.path_for(id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
        self.sync_dir()
    }
}

// --- Helpers for PSBT ↔ base64 conversion ---

/// Encode a PSBT as a base64 string.
pub fn psbt_to_base64(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

/// Decode a base64 string into a PSBT.
pub fn psbt_from_base64(s: &str) -> Result<Psbt> {
    let bytes = STANDARD.decode(s).context("base64 decode")?;
    Psbt::deserialize(&bytes).context("PSBT deserialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> FileSpendStore {
        let dir = std::env::temp_dir().join(format!(
            "ark-escrow-spend-store-{}-{}",
            std::process::id(),
            PendingSpend::new_token()
        ));
        FileSpendStore::new(dir).unwrap()
    }

    fn record(id: &str, token: &str) -> PendingSpend {
        PendingSpend {
            id: id.to_string(),
            ark_txid: "00".repeat(32),
            signed_checkpoints: vec![],
            stage: SpendStage::Submitting,
            token: token.to_string(),
            ark_tx: Some("psbt".to_string()),
            unsigned_checkpoints: vec!["cp".to_string()],
            party_signed_checkpoints: vec![vec!["a".to_string()], vec!["b".to_string()]],
            server_signed_ark_tx: None,
        }
    }

    #[test]
    fn round_trips_a_record() {
        let store = temp_store();
        let rec = record("trade-1", "tok");
        store.save(&rec).unwrap();
        let loaded = store.load("trade-1").unwrap().unwrap();
        assert_eq!(loaded.stage, SpendStage::Submitting);
        assert_eq!(loaded.token, "tok");
        assert_eq!(loaded.ark_tx.as_deref(), Some("psbt"));
        assert_eq!(loaded.party_signed_checkpoints.len(), 2);
    }

    #[test]
    fn save_overwrites_and_remove_if_checks_token() {
        let store = temp_store();
        store.save(&record("trade-1", "first")).unwrap();
        store.save(&record("trade-1", "second")).unwrap();

        // The first attempt must not delete the second attempt's record.
        assert!(!store.remove_if("trade-1", "first").unwrap());
        assert!(store.load("trade-1").unwrap().is_some());

        assert!(store.remove_if("trade-1", "second").unwrap());
        assert!(store.load("trade-1").unwrap().is_none());

        // Removing an absent record is not an error.
        assert!(!store.remove_if("trade-1", "second").unwrap());
        store.remove("trade-1").unwrap();
    }

    #[test]
    fn legacy_record_loads_as_submitted_and_matches_any_token() {
        let store = temp_store();
        let legacy = serde_json::json!({
            "id": "trade-legacy",
            "ark_txid": "11".repeat(32),
            "signed_checkpoints": ["cp"],
        });
        // Write the legacy shape directly, bypassing `save`.
        let path = store.path_for("trade-legacy");
        std::fs::write(&path, legacy.to_string()).unwrap();

        let loaded = store.load("trade-legacy").unwrap().unwrap();
        assert_eq!(loaded.stage, SpendStage::Submitted);
        assert!(loaded.token.is_empty());
        assert!(loaded.ark_tx.is_none());
        assert_eq!(loaded.signed_checkpoints, vec!["cp".to_string()]);

        assert!(store.remove_if("trade-legacy", "anything").unwrap());
        assert!(store.load("trade-legacy").unwrap().is_none());
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(PendingSpend::new_token(), PendingSpend::new_token());
        assert_eq!(PendingSpend::new_token().len(), 32);
    }
}
