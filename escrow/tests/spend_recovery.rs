//! Crash-recovery behaviour of `spend_escrow_offchain` against a fake server.
//!
//! The server never verifies signatures; it echoes submitted PSBTs back as
//! "signed". What is under test is the ordering of store writes relative to
//! the network calls, and what a retry does with each recorded stage.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ark_escrow::client::EscrowClient;
use ark_escrow::spend_store::{FileSpendStore, PendingSpend, SpendStage, SpendStore};
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use support::{Behavior, RefreshServer};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(50);

async fn connect(server: &RefreshServer) -> EscrowClient {
    let mut client = EscrowClient::new_with_timeout(&server.url, Duration::from_secs(3));
    client.connect().await.unwrap();
    client.set_timeout(Some(REQUEST_TIMEOUT));
    client
}

fn temp_store() -> FileSpendStore {
    FileSpendStore::new(std::env::temp_dir().join(format!(
        "ark-escrow-spend-recovery-{}-{}",
        std::process::id(),
        PendingSpend::new_token()
    )))
    .unwrap()
}

/// A one-input, one-output PSBT; `seed` makes distinct transactions.
fn psbt(seed: u8) -> Psbt {
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap();
    psbt.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![seed]));
    psbt
}

struct Spend {
    ark_tx: Psbt,
    checkpoints: Vec<Psbt>,
    party_a: Vec<Psbt>,
    party_b: Vec<Psbt>,
}

fn spend() -> Spend {
    Spend {
        ark_tx: psbt(1),
        checkpoints: vec![psbt(2), psbt(3)],
        party_a: vec![psbt(2), psbt(3)],
        party_b: vec![psbt(2), psbt(3)],
    }
}

async fn run(client: &EscrowClient, store: &FileSpendStore, id: &str) -> anyhow::Result<Txid> {
    let s = spend();
    tokio::time::timeout(
        Duration::from_secs(5),
        client.spend_escrow_offchain(
            store,
            id,
            s.ark_tx,
            s.checkpoints,
            &[&s.party_a, &s.party_b],
        ),
    )
    .await
    .expect("spend did not honor its timeout")
}

#[tokio::test]
async fn record_is_written_before_submit_and_a_retry_resubmits_it() {
    let server = RefreshServer::start(Behavior::StallSubmit).await;
    let client = connect(&server).await;
    let store = temp_store();
    let expected_txid = spend().ark_tx.unsigned_tx.compute_txid();

    let error = run(&client, &store, "trade").await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("submitting offchain transaction"),
        "{error:#}"
    );
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);

    // The lost-response case: the record exists although submit never returned.
    let pending = store
        .load("trade")
        .unwrap()
        .expect("record written before submit");
    assert_eq!(pending.stage, SpendStage::Submitting);
    assert_eq!(pending.ark_txid, expected_txid.to_string());
    assert!(pending.ark_tx.is_some());
    assert_eq!(pending.unsigned_checkpoints.len(), 2);
    assert_eq!(pending.party_signed_checkpoints.len(), 2);
    assert!(pending.signed_checkpoints.is_empty());
    assert!(!pending.token.is_empty());

    // A retry re-sends the recorded submit rather than reporting "no record".
    let _ = run(&client, &store, "trade").await.unwrap_err();
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 2);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);
    let retried = store.load("trade").unwrap().unwrap();
    assert_eq!(
        retried.token, pending.token,
        "retry keeps the original record"
    );
}

#[tokio::test]
async fn record_is_upgraded_after_submit_and_a_retry_only_finalizes() {
    let server = RefreshServer::start(Behavior::StallFinalize).await;
    let client = connect(&server).await;
    let store = temp_store();

    let error = run(&client, &store, "trade").await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("finalizing offchain transaction"),
        "{error:#}"
    );
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 1);

    let pending = store
        .load("trade")
        .unwrap()
        .expect("record kept after failed finalize");
    assert_eq!(pending.stage, SpendStage::Submitted);
    assert_eq!(pending.signed_checkpoints.len(), 2);
    assert!(pending.ark_tx.is_none());
    assert!(pending.unsigned_checkpoints.is_empty());

    // A retry must not resubmit: the inputs are locked server-side.
    let _ = run(&client, &store, "trade").await.unwrap_err();
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn successful_spend_removes_its_own_record_only() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    let txid = run(&client, &store, "trade").await.unwrap();
    assert_eq!(txid, spend().ark_tx.unsigned_tx.compute_txid());
    assert!(store.load("trade").unwrap().is_none());

    // A legacy record (no stage, no token) resumes at finalize and is cleared.
    store
        .save(&PendingSpend {
            id: "legacy".to_string(),
            ark_txid: txid.to_string(),
            signed_checkpoints: vec![ark_escrow::spend_store::psbt_to_base64(&psbt(2))],
            stage: SpendStage::Submitted,
            token: String::new(),
            ark_tx: None,
            unsigned_checkpoints: vec![],
            party_signed_checkpoints: vec![],
        })
        .unwrap();
    let submits_before = server.submit_requests.load(Ordering::SeqCst);
    assert_eq!(run(&client, &store, "legacy").await.unwrap(), txid);
    assert_eq!(
        server.submit_requests.load(Ordering::SeqCst),
        submits_before
    );
    assert!(store.load("legacy").unwrap().is_none());
}

#[tokio::test]
async fn finished_attempt_does_not_delete_a_record_it_did_not_write() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    // Simulate a concurrent attempt replacing the record mid-flight: a store
    // wrapper swaps in a foreign record on the `Submitted` save.
    struct Swapping<'a>(&'a FileSpendStore);
    impl SpendStore for Swapping<'_> {
        fn save(&self, spend: &PendingSpend) -> anyhow::Result<()> {
            let mut other = spend.clone();
            if spend.stage == SpendStage::Submitted {
                other.token = "foreign".to_string();
            }
            self.0.save(&other)
        }
        fn load(&self, id: &str) -> anyhow::Result<Option<PendingSpend>> {
            self.0.load(id)
        }
        fn remove(&self, id: &str) -> anyhow::Result<()> {
            self.0.remove(id)
        }
    }

    let s = spend();
    let txid = client
        .spend_escrow_offchain(
            &Swapping(&store),
            "trade",
            s.ark_tx,
            s.checkpoints,
            &[&s.party_a, &s.party_b],
        )
        .await
        .unwrap();
    assert_eq!(txid, spend().ark_tx.unsigned_tx.compute_txid());

    let remaining = store
        .load("trade")
        .unwrap()
        .expect("foreign record survives");
    assert_eq!(remaining.token, "foreign");
}
