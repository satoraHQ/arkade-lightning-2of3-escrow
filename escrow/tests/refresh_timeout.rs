mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ark_core::intent::{Intent, IntentMessage};
use ark_escrow::client::EscrowClient;
use ark_escrow::refresh::RefreshIntent;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Psbt, Transaction, Txid, absolute, transaction};
use support::{Behavior, RefreshServer};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(20);
const REGISTRATION_DELAY: Duration = Duration::from_millis(200);

async fn connect(server: &RefreshServer) -> EscrowClient {
    let mut client = EscrowClient::new_with_timeout(&server.url, Duration::from_secs(3));
    client.connect().await.unwrap();
    client.set_timeout(Some(REQUEST_TIMEOUT));
    client
}

async fn refresh(client: &EscrowClient) -> anyhow::Result<Txid> {
    let cosigner = Keypair::from_seckey_slice(&Secp256k1::new(), &[9; 32]).unwrap();
    let proof = Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
    .unwrap();
    let refresh = RefreshIntent {
        intent: Intent::new(
            proof,
            IntentMessage::Register {
                onchain_output_indexes: vec![],
                valid_at: 0,
                expire_at: 0,
                own_cosigner_pks: vec![cosigner.public_key()],
            },
        ),
        forfeit_psbts: vec![],
        refresh_cosigner_pk: cosigner.public_key(),
        delete_intent: None,
    };
    // Bound regressions that accidentally remove the refresh deadline entirely.
    tokio::time::timeout(
        Duration::from_secs(5),
        client.refresh_escrow(refresh, cosigner),
    )
    .await
    .expect("refresh failed to honor its deadline")
}

#[tokio::test]
async fn default_refresh_deadline_outlasts_short_request_timeout() {
    let server = RefreshServer::start(Behavior::DelayRegistration(REGISTRATION_DELAY)).await;
    let client = connect(&server).await;
    assert_eq!(client.refresh_timeout(), Some(Duration::from_secs(120)));

    let error = refresh(&client).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("refresh reached event stream"),
        "refresh should progress beyond registration: {error:#}"
    );
}

#[tokio::test]
async fn custom_refresh_deadline_bounds_stalled_registration() {
    let server = RefreshServer::start(Behavior::StallRegistration).await;
    let mut client = connect(&server).await;
    client.set_refresh_timeout(Some(Duration::from_millis(100)));
    // Updating the ordinary timeout must not overwrite the refresh deadline.
    client.set_timeout(Some(Duration::from_secs(3)));

    let error = refresh(&client).await.unwrap_err();
    assert_eq!(error.to_string(), "refreshing escrow timed out after 100ms");
}

#[tokio::test]
async fn refresh_deadline_also_bounds_waiting_for_the_event_stream() {
    let server = RefreshServer::start(Behavior::StallStream).await;
    let mut client = connect(&server).await;
    client.set_refresh_timeout(Some(Duration::from_millis(200)));

    let error = refresh(&client).await.unwrap_err();
    assert_eq!(error.to_string(), "refreshing escrow timed out after 200ms");
    assert!(server.stream_requested.load(Ordering::SeqCst));
}

#[tokio::test]
async fn ordinary_requests_still_use_the_short_timeout() {
    let server = RefreshServer::start(Behavior::StallInfo).await;
    let mut client = EscrowClient::new_with_timeout(&server.url, Duration::from_millis(100));
    client.set_refresh_timeout(Some(Duration::from_secs(120)));

    let error = tokio::time::timeout(Duration::from_secs(5), client.connect())
        .await
        .expect("connect ignored its request timeout")
        .unwrap_err();
    assert!(format!("{error:#}").contains("timed out after 100ms"));
}

#[tokio::test]
async fn disabling_refresh_deadline_does_not_reuse_request_timeout() {
    let server = RefreshServer::start(Behavior::DelayRegistration(REGISTRATION_DELAY)).await;
    let mut client = connect(&server).await;
    client.set_refresh_timeout(None);
    let client = client.clone();
    assert_eq!(client.refresh_timeout(), None);
    assert_eq!(client.timeout(), Some(REQUEST_TIMEOUT));

    let error = refresh(&client).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("refresh reached event stream"),
        "refresh should progress beyond registration: {error:#}"
    );
}
