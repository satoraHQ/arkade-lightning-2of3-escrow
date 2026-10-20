//! Crash-recovery and server-commitment behaviour of `spend_escrow_offchain`
//! against a fake server.
//!
//! The server never verifies party signatures; it co-signs the ark tx with a
//! chosen key (through the same ark-core signing path a real signer uses) and
//! echoes submitted checkpoints back as "signed". What is under test is the
//! ordering of store writes relative to the network calls, what a retry does
//! with each recorded stage, and that party checkpoint signatures are only
//! released once the server's co-signature has been verified.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ark_escrow::client::EscrowClient;
use ark_escrow::contract::{EscrowContract, EscrowOptions, SignerSet};
use ark_escrow::spend::{self, EscrowVtxo};
use ark_escrow::spend_store::{
    FileSpendStore, PendingSpend, SpendStage, SpendStore, psbt_from_base64, psbt_to_base64,
};
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use support::{ACTIVE_SIGNER_SEED, Behavior, DEPRECATED_SIGNER_SEED, RefreshServer};

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

/// An opaque one-input PSBT for hand-written records; `seed` makes distinct
/// transactions.
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

impl Spend {
    fn txid(&self) -> Txid {
        self.ark_tx.unsigned_tx.compute_txid()
    }
}

/// A real buyer+arbiter release of an escrow whose server key is
/// `server_seed`, built with `build_release_tx` and signed by both parties
/// exactly as the exchange does it.
fn spend_for_server(client: &EscrowClient, server_seed: u8) -> Spend {
    let info = client.server_info().unwrap();
    let [seller, buyer, arbiter] = [11u8, 12, 13].map(support::keypair);
    let contract = EscrowContract::new(
        EscrowOptions {
            seller: seller.x_only_public_key().0,
            buyer: buyer.x_only_public_key().0,
            arbiter: arbiter.x_only_public_key().0,
            server: support::keypair(server_seed).x_only_public_key().0,
            unilateral_exit_delay: info.unilateral_exit_delay,
        },
        info.network,
    )
    .unwrap();
    let vtxo = EscrowVtxo {
        outpoint: OutPoint::new(Txid::from_byte_array([42; 32]), 1),
        amount: Amount::from_sat(100_000),
    };
    let release = spend::build_release_tx(
        &contract,
        &vtxo,
        &contract.address(),
        &[],
        SignerSet::BuyerArbiter,
        &info,
    )
    .unwrap();

    let mut ark_tx = release.ark_tx.clone();
    spend::sign_ark_tx(&mut ark_tx, &buyer).unwrap();
    let mut arbiter_copy = release.ark_tx.clone();
    spend::sign_ark_tx(&mut arbiter_copy, &arbiter).unwrap();
    spend::merge_ark_tx_sigs(&mut ark_tx, &arbiter_copy).unwrap();

    let sign_all = |kp: &bitcoin::key::Keypair| -> Vec<Psbt> {
        release
            .checkpoint_txs
            .iter()
            .map(|cp| {
                let mut cp = cp.clone();
                spend::sign_checkpoint(&mut cp, kp).unwrap();
                cp
            })
            .collect()
    };
    Spend {
        ark_tx,
        checkpoints: release.checkpoint_txs.clone(),
        party_a: sign_all(&buyer),
        party_b: sign_all(&arbiter),
    }
}

fn spend(client: &EscrowClient) -> Spend {
    spend_for_server(client, ACTIVE_SIGNER_SEED)
}

async fn run_spend(
    client: &EscrowClient,
    store: &(impl SpendStore + ?Sized),
    id: &str,
    s: Spend,
) -> anyhow::Result<Txid> {
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

async fn run(client: &EscrowClient, store: &FileSpendStore, id: &str) -> anyhow::Result<Txid> {
    run_spend(client, store, id, spend(client)).await
}

fn chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[tokio::test]
async fn record_is_written_before_submit_and_a_retry_resubmits_it() {
    let server = RefreshServer::start(Behavior::StallSubmit).await;
    let client = connect(&server).await;
    let store = temp_store();
    let expected_txid = spend(&client).txid();

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
    assert_eq!(pending.unsigned_checkpoints.len(), 1);
    assert_eq!(pending.party_signed_checkpoints.len(), 2);
    assert!(pending.signed_checkpoints.is_empty());
    assert!(pending.server_signed_ark_tx.is_none());
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
    assert_eq!(pending.signed_checkpoints.len(), 1);
    assert!(pending.ark_tx.is_none());
    assert!(pending.unsigned_checkpoints.is_empty());
    let cosigned = psbt_from_base64(pending.server_signed_ark_tx.as_deref().unwrap()).unwrap();
    assert_eq!(cosigned.unsigned_tx, spend(&client).ark_tx.unsigned_tx);
    assert_eq!(
        cosigned.inputs[0].tap_script_sigs.len(),
        3,
        "2 parties + server"
    );
    assert!(
        cosigned.inputs[0].witness_utxo.is_some(),
        "canonical copy keeps local data"
    );

    // A retry must not resubmit: the inputs are locked server-side.
    let _ = run(&client, &store, "trade").await.unwrap_err();
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn successful_spend_keeps_a_finalized_record_and_resumes_without_a_server_call() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    let txid = run(&client, &store, "trade").await.unwrap();
    assert_eq!(txid, spend(&client).txid());
    assert_eq!(
        server.submitted_checkpoint_sigs.load(Ordering::SeqCst),
        0,
        "party checkpoint signatures never travel in submit"
    );

    let finalized = store.load("trade").unwrap().expect("finalized record kept");
    assert_eq!(finalized.stage, SpendStage::Finalized);
    let cosigned = psbt_from_base64(finalized.server_signed_ark_tx.as_deref().unwrap()).unwrap();
    assert_eq!(
        cosigned.inputs[0].tap_script_sigs.len(),
        3,
        "2 parties + server"
    );
    assert_eq!(finalized.signed_checkpoints.len(), 1);

    let (submits, finalizes) = (
        server.submit_requests.load(Ordering::SeqCst),
        server.finalize_requests.load(Ordering::SeqCst),
    );
    assert_eq!(run(&client, &store, "trade").await.unwrap(), txid);
    assert_eq!(
        client.resume_pending_spend(&store, "trade").await.unwrap(),
        Some(txid)
    );
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), submits);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), finalizes);
}

#[tokio::test]
async fn legacy_submitted_record_without_cosignature_is_not_finalized() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    // Written by a version that did not verify or keep the server's ark tx.
    store
        .save(&PendingSpend {
            id: "legacy".to_string(),
            ark_txid: spend(&client).txid().to_string(),
            signed_checkpoints: vec![psbt_to_base64(&psbt(2))],
            stage: SpendStage::Submitted,
            token: String::new(),
            ark_tx: None,
            unsigned_checkpoints: vec![],
            party_signed_checkpoints: vec![],
            server_signed_ark_tx: None,
        })
        .unwrap();

    let error = run(&client, &store, "legacy").await.unwrap_err();
    assert!(
        chain(&error).contains("no verified server co-signature"),
        "{error:#}"
    );
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 0);
    assert!(
        store.load("legacy").unwrap().is_some(),
        "left for the operator"
    );
}

#[tokio::test]
async fn finished_attempt_does_not_overwrite_a_record_it_did_not_write() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    // Simulate a concurrent attempt replacing the record mid-flight: a store
    // wrapper swaps in a foreign token on the `Submitted` save.
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

    let txid = run_spend(&client, &Swapping(&store), "trade", spend(&client))
        .await
        .unwrap();
    assert_eq!(txid, spend(&client).txid());

    let remaining = store
        .load("trade")
        .unwrap()
        .expect("foreign record survives");
    assert_eq!(remaining.token, "foreign");
    assert_eq!(
        remaining.stage,
        SpendStage::Submitted,
        "not marked finalized by us"
    );
}

#[tokio::test]
async fn definitive_rejection_on_first_attempt_clears_the_record() {
    let server = RefreshServer::start(Behavior::RejectSubmit).await;
    let client = connect(&server).await;
    let store = temp_store();

    let error = run(&client, &store, "trade").await.unwrap_err();
    assert!(
        error.to_string().contains("rejected by server"),
        "{error:#}"
    );
    assert!(
        store.load("trade").unwrap().is_none(),
        "a rejected first attempt must not poison the id"
    );

    // A corrected retry is a fresh submit, not a replay.
    let _ = run(&client, &store, "trade").await.unwrap_err();
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn definitive_rejection_on_resume_keeps_the_record() {
    let server = RefreshServer::start(Behavior::RejectSubmit).await;
    let client = connect(&server).await;
    let store = temp_store();

    // A record left by a lost first attempt (as if the process died).
    let s = spend(&client);
    store
        .save(&PendingSpend {
            id: "trade".to_string(),
            ark_txid: s.txid().to_string(),
            signed_checkpoints: vec![],
            stage: SpendStage::Submitting,
            token: "orig".to_string(),
            ark_tx: Some(psbt_to_base64(&s.ark_tx)),
            unsigned_checkpoints: s.checkpoints.iter().map(psbt_to_base64).collect(),
            party_signed_checkpoints: vec![
                s.party_a.iter().map(psbt_to_base64).collect(),
                s.party_b.iter().map(psbt_to_base64).collect(),
            ],
            server_signed_ark_tx: None,
        })
        .unwrap();

    // The rejection may be "inputs already locked" by our own earlier submit.
    let error = client
        .resume_pending_spend(&store, "trade")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("retained"), "{error:#}");
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);
    let kept = store
        .load("trade")
        .unwrap()
        .expect("record kept for operator");
    assert_eq!(kept.stage, SpendStage::Submitting);
    assert_eq!(kept.token, "orig");
}

#[tokio::test]
async fn resume_pending_spend_finalizes_a_submitted_record_or_reports_none() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    assert!(
        client
            .resume_pending_spend(&store, "trade")
            .await
            .unwrap()
            .is_none()
    );

    // A `submitted` record as left by a crash after submit, with genuine
    // evidence from the server.
    let stalled = RefreshServer::start(Behavior::StallFinalize).await;
    let stalled_client = connect(&stalled).await;
    let txid = spend(&stalled_client).txid();
    let _ = run(&stalled_client, &store, "trade").await.unwrap_err();
    assert_eq!(
        store.load("trade").unwrap().unwrap().stage,
        SpendStage::Submitted
    );

    assert_eq!(
        client.resume_pending_spend(&store, "trade").await.unwrap(),
        Some(txid)
    );
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 0);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.load("trade").unwrap().unwrap().stage,
        SpendStage::Finalized
    );
}

#[tokio::test]
async fn mismatched_party_checkpoints_are_rejected_before_anything_is_sent_or_written() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    let mut s = spend(&client);
    // Same length, but the second party signed a different transaction.
    s.party_b = s.checkpoints.iter().map(|_| psbt(9)).collect();
    let error = run_spend(&client, &store, "trade", s).await.unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error:#}");
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 0);
    assert!(store.load("trade").unwrap().is_none());
}

#[tokio::test]
async fn submitted_stage_is_persisted_after_a_failed_finalize_even_if_the_first_save_failed() {
    let server = RefreshServer::start(Behavior::StallFinalize).await;
    let client = connect(&server).await;
    let store = temp_store();

    // Fails the `Submitted` save exactly once.
    struct FlakySubmittedSave<'a> {
        inner: &'a FileSpendStore,
        failed_once: std::sync::atomic::AtomicBool,
    }
    impl SpendStore for FlakySubmittedSave<'_> {
        fn save(&self, spend: &PendingSpend) -> anyhow::Result<()> {
            if spend.stage == SpendStage::Submitted
                && !self.failed_once.swap(true, Ordering::SeqCst)
            {
                anyhow::bail!("disk full");
            }
            self.inner.save(spend)
        }
        fn load(&self, id: &str) -> anyhow::Result<Option<PendingSpend>> {
            self.inner.load(id)
        }
        fn remove(&self, id: &str) -> anyhow::Result<()> {
            self.inner.remove(id)
        }
    }
    let flaky = FlakySubmittedSave {
        inner: &store,
        failed_once: std::sync::atomic::AtomicBool::new(false),
    };

    let error = run_spend(&client, &flaky, "trade", spend(&client))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("finalizing"), "{error:#}");

    let pending = store.load("trade").unwrap().unwrap();
    assert_eq!(
        pending.stage,
        SpendStage::Submitted,
        "retried save kept the server sigs"
    );
    assert_eq!(pending.signed_checkpoints.len(), 1);
    assert!(pending.server_signed_ark_tx.is_some());
}

#[tokio::test]
async fn missing_server_cosignature_withholds_finalize_and_keeps_the_record() {
    let server = RefreshServer::start(Behavior::AcceptWithoutCosigning).await;
    let client = connect(&server).await;
    let store = temp_store();

    let error = run(&client, &store, "trade").await.unwrap_err();
    assert!(chain(&error).contains("did not co-sign"), "{error:#}");
    // Party checkpoint signatures were never released, on either leg.
    assert_eq!(server.submitted_checkpoint_sigs.load(Ordering::SeqCst), 0);
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);
    let pending = store.load("trade").unwrap().expect("record kept");
    assert_eq!(pending.stage, SpendStage::Submitting);
    assert!(pending.server_signed_ark_tx.is_none());
}

#[tokio::test]
async fn a_deprecated_server_key_is_accepted_only_for_a_contract_that_names_it() {
    // Contract on the deprecated key, co-signed by the deprecated key: fine.
    let server = RefreshServer::start(Behavior::AcceptCosignedBy(DEPRECATED_SIGNER_SEED)).await;
    let client = connect(&server).await;
    let store = temp_store();

    // The fake server really announces the deprecated signer (the test would
    // otherwise pass for the wrong reason).
    let info = client.server_info().unwrap();
    assert_eq!(info.deprecated_signers.len(), 1);
    assert_eq!(
        info.deprecated_signers[0].pk,
        support::keypair(DEPRECATED_SIGNER_SEED).public_key()
    );
    assert_eq!(info.deprecated_signers[0].cutoff_date, i64::MAX);
    assert_eq!(info.signer_pk, support::server_keypair().public_key());
    run_spend(
        &client,
        &store,
        "old",
        spend_for_server(&client, DEPRECATED_SIGNER_SEED),
    )
    .await
    .unwrap();
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 1);

    // Same contract, co-signed by the *active* key, which is announced but not
    // in the leaf: the signature cannot spend the leaf, so it is refused.
    let server = RefreshServer::start(Behavior::AcceptCosignedBy(ACTIVE_SIGNER_SEED)).await;
    let client = connect(&server).await;
    let error = run_spend(
        &client,
        &store,
        "old2",
        spend_for_server(&client, DEPRECATED_SIGNER_SEED),
    )
    .await
    .unwrap_err();
    assert!(chain(&error).contains("did not co-sign"), "{error:#}");
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);

    // And a contract on the active key co-signed by the deprecated one.
    let server = RefreshServer::start(Behavior::AcceptCosignedBy(DEPRECATED_SIGNER_SEED)).await;
    let client = connect(&server).await;
    let error = run_spend(&client, &store, "new", spend(&client))
        .await
        .unwrap_err();
    assert!(chain(&error).contains("did not co-sign"), "{error:#}");
    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_id_is_bound_to_one_transaction() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    let txid = run(&client, &store, "trade").await.unwrap();

    // A different escrow (other server key, other leaf) under the same id.
    let other = spend_for_server(&client, DEPRECATED_SIGNER_SEED);
    assert_ne!(other.txid(), txid);
    let error = run_spend(&client, &store, "trade", other)
        .await
        .unwrap_err();
    assert!(chain(&error).contains("already bound"), "{error:#}");
    assert_eq!(server.submit_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.load("trade").unwrap().unwrap().ark_txid,
        txid.to_string()
    );
}

#[tokio::test]
async fn tampered_or_unverifiable_stored_evidence_is_not_finalized() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();
    let s = spend(&client);

    let other = spend_for_server(&client, DEPRECATED_SIGNER_SEED);
    let record = |evidence: &Psbt| PendingSpend {
        id: "trade".to_string(),
        ark_txid: s.txid().to_string(),
        signed_checkpoints: vec![psbt_to_base64(&psbt(2))],
        stage: SpendStage::Submitted,
        token: "t".to_string(),
        ark_tx: None,
        unsigned_checkpoints: vec![],
        party_signed_checkpoints: vec![],
        server_signed_ark_tx: Some(psbt_to_base64(evidence)),
    };

    // Evidence for the wrong transaction.
    store.save(&record(&other.ark_tx)).unwrap();
    let error = client
        .resume_pending_spend(&store, "trade")
        .await
        .unwrap_err();
    assert!(
        chain(&error).contains("does not match recorded ark txid"),
        "{error:#}"
    );

    // Right transaction, but no server signature on it.
    store.save(&record(&s.ark_tx)).unwrap();
    let error = client
        .resume_pending_spend(&store, "trade")
        .await
        .unwrap_err();
    assert!(chain(&error).contains("did not co-sign"), "{error:#}");

    // Genuine evidence, but checkpoints that are not inputs of that ark tx.
    let stalled = RefreshServer::start(Behavior::StallFinalize).await;
    let stalled_client = connect(&stalled).await;
    let _ = run(&stalled_client, &store, "genuine").await.unwrap_err();
    let mut genuine = store.load("genuine").unwrap().unwrap();
    assert_eq!(genuine.stage, SpendStage::Submitted);
    genuine.signed_checkpoints = vec![psbt_to_base64(&psbt(2))];
    store.save(&genuine).unwrap();
    let error = client
        .resume_pending_spend(&store, "genuine")
        .await
        .unwrap_err();
    assert!(
        chain(&error).contains("not inputs of the recorded ark tx"),
        "{error:#}"
    );

    assert_eq!(server.finalize_requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.load("trade").unwrap().unwrap().stage,
        SpendStage::Submitted
    );
}

#[tokio::test]
async fn finalized_mark_does_not_overwrite_a_record_replaced_after_finalize() {
    let server = RefreshServer::start(Behavior::AcceptSpend).await;
    let client = connect(&server).await;
    let store = temp_store();

    // A store whose `save_if` sees a foreign record at the moment of the
    // finalized write (as an atomic backend would).
    struct ReplacedBeforeFinalize<'a>(&'a FileSpendStore);
    impl SpendStore for ReplacedBeforeFinalize<'_> {
        fn save(&self, spend: &PendingSpend) -> anyhow::Result<()> {
            self.0.save(spend)
        }
        fn load(&self, id: &str) -> anyhow::Result<Option<PendingSpend>> {
            self.0.load(id)
        }
        fn remove(&self, id: &str) -> anyhow::Result<()> {
            self.0.remove(id)
        }
        fn save_if(&self, spend: &PendingSpend) -> anyhow::Result<bool> {
            let mut foreign = spend.clone();
            foreign.token = "foreign".to_string();
            foreign.stage = SpendStage::Submitting;
            self.0.save(&foreign)?;
            self.0.save_if(spend)
        }
    }

    let txid = run_spend(
        &client,
        &ReplacedBeforeFinalize(&store),
        "trade",
        spend(&client),
    )
    .await
    .unwrap();
    assert_eq!(txid, spend(&client).txid());
    let remaining = store.load("trade").unwrap().unwrap();
    assert_eq!(remaining.token, "foreign");
    assert_eq!(remaining.stage, SpendStage::Submitting);
}
