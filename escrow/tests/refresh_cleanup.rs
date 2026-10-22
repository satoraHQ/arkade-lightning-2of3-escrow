//! Stale-intent handling around the refresh ceremony, against a fake server.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ark_core::intent::{Intent, IntentMessage};
use ark_escrow::client::EscrowClient;
use ark_escrow::refresh::RefreshIntent;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Psbt, Transaction, absolute, transaction};
use support::{Behavior, RefreshServer};

async fn connect(server: &RefreshServer) -> EscrowClient {
    let mut client = EscrowClient::new_with_timeout(&server.url, Duration::from_secs(3));
    client.connect().await.unwrap();
    client
}

fn empty_proof() -> Psbt {
    Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
    .unwrap()
}

fn refresh_intent(with_delete: bool) -> (RefreshIntent, Keypair) {
    let cosigner = Keypair::from_seckey_slice(&Secp256k1::new(), &[9; 32]).unwrap();
    let refresh = RefreshIntent {
        intent: Intent::new(
            empty_proof(),
            IntentMessage::Register {
                onchain_output_indexes: vec![],
                valid_at: 0,
                expire_at: 0,
                own_cosigner_pks: vec![cosigner.public_key()],
            },
        ),
        forfeit_psbts: vec![],
        refresh_cosigner_pk: cosigner.public_key(),
        delete_intent: with_delete.then(|| {
            Intent::new(
                empty_proof(),
                IntentMessage::Delete {
                    expire_at: u64::MAX,
                },
            )
        }),
    };
    (refresh, cosigner)
}

#[tokio::test]
async fn a_stale_intent_is_deleted_and_registration_retried_once() {
    let server = RefreshServer::start(Behavior::StaleIntentOnce).await;
    let client = connect(&server).await;
    let (refresh, cosigner) = refresh_intent(true);

    // The fake's event stream ends the ceremony with an error once reached,
    // which is as far as a fake can take it.
    let error = client.refresh_escrow(refresh, cosigner).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("refresh reached event stream"),
        "{error:#}"
    );
    assert_eq!(server.register_requests.load(Ordering::SeqCst), 2);
    // One delete for the stale intent, one to withdraw ours after the failure.
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn without_a_delete_proof_a_stale_intent_is_reported_as_is() {
    let server = RefreshServer::start(Behavior::StaleIntentOnce).await;
    let client = connect(&server).await;
    let (refresh, cosigner) = refresh_intent(false);

    let error = client.refresh_escrow(refresh, cosigner).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("already registered"),
        "{error:#}"
    );
    assert_eq!(server.register_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_timed_out_ceremony_withdraws_its_intent() {
    let server = RefreshServer::start(Behavior::StallStream).await;
    let mut client = connect(&server).await;
    client.set_refresh_timeout(Some(Duration::from_millis(200)));
    let (refresh, cosigner) = refresh_intent(true);

    let error = client.refresh_escrow(refresh, cosigner).await.unwrap_err();
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert_eq!(server.register_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_stale_intent_inside_a_running_batch_is_deleted_on_a_later_try() {
    let server = RefreshServer::start(Behavior::StaleIntentNoMatchOnce).await;
    let client = connect(&server).await;
    let (refresh, cosigner) = refresh_intent(true);

    let error = client.refresh_escrow(refresh, cosigner).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("refresh reached event stream"),
        "{error:#}"
    );
    assert_eq!(server.register_requests.load(Ordering::SeqCst), 2);
    // no-match, then deleted, then the withdrawal after the stream error.
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_failed_withdrawal_does_not_mask_the_ceremony_error() {
    let server = RefreshServer::start(Behavior::StallStreamDeleteFails).await;
    let mut client = connect(&server).await;
    client.set_refresh_timeout(Some(Duration::from_millis(200)));
    let (refresh, cosigner) = refresh_intent(true);

    let error = client.refresh_escrow(refresh, cosigner).await.unwrap_err();
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert!(!format!("{error:#}").contains("boom"), "{error:#}");
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn withdrawal_is_bounded_even_when_the_request_timeout_is_disabled() {
    let server = RefreshServer::start(Behavior::StallStream).await;
    let mut client = connect(&server).await;
    client.set_timeout(None);
    client.set_refresh_timeout(Some(Duration::from_millis(200)));
    let (refresh, cosigner) = refresh_intent(true);
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.refresh_escrow(refresh, cosigner),
    )
    .await
    .expect("cleanup must not hang")
    .unwrap_err();
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert_eq!(server.delete_requests.load(Ordering::SeqCst), 1);
}
