// Shared by several test binaries; each uses a subset of it.
#![allow(dead_code)]

pub mod regtest;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ark_grpc::test_utils::GetInfoResponse;
use bitcoin::key::{Keypair, Secp256k1};
use bytes::{BufMut, Bytes, BytesMut};
use prost::Message;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

/// Minimal local endpoint for exercising the real refresh request path. It can
/// delay registration or stall the event stream, without simulating signatures
/// or claiming to complete a valid batch ceremony.
pub struct RefreshServer {
    pub url: String,
    pub stream_requested: Arc<AtomicBool>,
    /// Number of `SubmitTx` requests received.
    pub submit_requests: Arc<AtomicUsize>,
    /// Number of `FinalizeTx` requests received.
    pub finalize_requests: Arc<AtomicUsize>,
    /// Total `tap_script_sigs` seen on checkpoints in `SubmitTx` requests.
    /// Must stay 0: party checkpoint signatures never travel in submit.
    pub submitted_checkpoint_sigs: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for RefreshServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy)]
pub enum Behavior {
    DelayRegistration(Duration),
    StallInfo,
    StallRegistration,
    StallStream,
    /// `SubmitTx` never answers. The client cannot tell whether it was
    /// accepted.
    StallSubmit,
    /// `SubmitTx` echoes the submitted PSBTs back as "signed"; `FinalizeTx`
    /// never answers.
    StallFinalize,
    /// `SubmitTx` echoes the submitted PSBTs back; `FinalizeTx` succeeds.
    AcceptSpend,
    /// `SubmitTx` answers with gRPC `InvalidArgument`.
    RejectSubmit,
    /// `SubmitTx` echoes the PSBTs back without co-signing the ark tx.
    AcceptWithoutCosigning,
    /// `SubmitTx` co-signs the ark tx with the key derived from this seed
    /// instead of the active signer key; `FinalizeTx` succeeds.
    AcceptCosignedBy(u8),
}

/// Seed of the fake server's active signer key (`signer_pubkey` in `GetInfo`).
pub const ACTIVE_SIGNER_SEED: u8 = 7;
/// Seed of the one deprecated signer the fake server announces.
pub const DEPRECATED_SIGNER_SEED: u8 = 8;

/// A keypair from a one-byte seed.
pub fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32]).unwrap()
}

/// The fake server's active signing key.
pub fn server_keypair() -> Keypair {
    keypair(ACTIVE_SIGNER_SEED)
}

/// Co-sign input 0 of a base64 ark tx PSBT through the same ark-core signing
/// path a real signer uses, and strip the party data a real server would not
/// echo back.
fn cosign_ark_tx(ark_tx_b64: &str, seed: u8) -> String {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    let mut psbt = bitcoin::Psbt::deserialize(&STANDARD.decode(ark_tx_b64).unwrap()).unwrap();
    let party_sigs = std::mem::take(&mut psbt.inputs[0].tap_script_sigs);
    ark_escrow::spend::sign_ark_tx(&mut psbt, &keypair(seed)).unwrap();
    assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
    assert!(
        party_sigs
            .keys()
            .all(|k| !psbt.inputs[0].tap_script_sigs.contains_key(k))
    );
    STANDARD.encode(psbt.serialize())
}

/// Number of `tap_script_sigs` across all checkpoints in a `SubmitTx` request.
fn checkpoint_sig_count(checkpoints: &[String]) -> usize {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    checkpoints
        .iter()
        .map(|b64| {
            let psbt = bitcoin::Psbt::deserialize(&STANDARD.decode(b64).unwrap()).unwrap();
            psbt.inputs
                .iter()
                .map(|i| i.tap_script_sigs.len())
                .sum::<usize>()
        })
        .sum()
}

#[derive(Message)]
struct SubmitTxRequest {
    #[prost(string, tag = "1")]
    signed_ark_tx: String,
    #[prost(string, repeated, tag = "2")]
    checkpoint_txs: Vec<String>,
}

#[derive(Message)]
struct SubmitTxResponse {
    #[prost(string, tag = "1")]
    ark_txid: String,
    #[prost(string, tag = "2")]
    final_ark_tx: String,
    #[prost(string, repeated, tag = "3")]
    signed_checkpoint_txs: Vec<String>,
}

/// Read a unary gRPC request body and strip the 5-byte length prefix.
async fn read_grpc_message(body: &mut h2::RecvStream) -> Bytes {
    let mut buf = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    buf.split_off(5).freeze()
}

#[derive(Message)]
struct RegisterIntentResponse {
    #[prost(string, tag = "1")]
    intent_id: String,
}

impl RefreshServer {
    pub async fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let info = server_info_bytes();
        let stream_requested = Arc::new(AtomicBool::new(false));
        let stream_observed = stream_requested.clone();
        let submit_requests = Arc::new(AtomicUsize::new(0));
        let submit_counter = submit_requests.clone();
        let finalize_requests = Arc::new(AtomicUsize::new(0));
        let finalize_counter = finalize_requests.clone();
        let submitted_checkpoint_sigs = Arc::new(AtomicUsize::new(0));
        let cp_sig_counter = submitted_checkpoint_sigs.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let info = info.clone();
                let stream_observed = stream_observed.clone();
                let submit_counter = submit_counter.clone();
                let finalize_counter = finalize_counter.clone();
                let cp_sig_counter = cp_sig_counter.clone();
                connections.spawn(async move {
                    let mut connection = h2::server::handshake(socket).await.unwrap();
                    let mut requests = JoinSet::new();
                    while let Some(request) = connection.accept().await {
                        let (request, mut response) = request.unwrap();
                        let info = info.clone();
                        let stream_observed = stream_observed.clone();
                        let submit_counter = submit_counter.clone();
                        let finalize_counter = finalize_counter.clone();
                        let cp_sig_counter = cp_sig_counter.clone();
                        requests.spawn(async move {
                            let (parts, mut body) = request.into_parts();
                            let payload = match parts.uri.path() {
                                "/ark.v1.ArkService/SubmitTx" => {
                                    submit_counter.fetch_add(1, Ordering::SeqCst);
                                    let req =
                                        SubmitTxRequest::decode(read_grpc_message(&mut body).await)
                                            .unwrap();
                                    cp_sig_counter.fetch_add(
                                        checkpoint_sig_count(&req.checkpoint_txs),
                                        Ordering::SeqCst,
                                    );
                                    if matches!(behavior, Behavior::StallSubmit) {
                                        std::future::pending::<()>().await;
                                    }
                                    if matches!(behavior, Behavior::RejectSubmit) {
                                        let headers = http::Response::builder()
                                            .header("content-type", "application/grpc")
                                            .header("grpc-status", "3")
                                            .header("grpc-message", "invalid ark psbt")
                                            .body(())
                                            .unwrap();
                                        let _ = response.send_response(headers, true);
                                        return;
                                    }
                                    let final_ark_tx = match behavior {
                                        Behavior::AcceptWithoutCosigning => req.signed_ark_tx,
                                        Behavior::AcceptCosignedBy(seed) => {
                                            cosign_ark_tx(&req.signed_ark_tx, seed)
                                        }
                                        _ => cosign_ark_tx(&req.signed_ark_tx, ACTIVE_SIGNER_SEED),
                                    };
                                    SubmitTxResponse {
                                        ark_txid: String::new(),
                                        final_ark_tx,
                                        signed_checkpoint_txs: req.checkpoint_txs,
                                    }
                                    .encode_to_vec()
                                }
                                "/ark.v1.ArkService/FinalizeTx" => {
                                    finalize_counter.fetch_add(1, Ordering::SeqCst);
                                    if matches!(behavior, Behavior::StallFinalize) {
                                        std::future::pending::<()>().await;
                                    }
                                    Vec::new()
                                }
                                "/ark.v1.ArkService/GetInfo" => {
                                    if matches!(behavior, Behavior::StallInfo) {
                                        std::future::pending::<()>().await;
                                    }
                                    info
                                }
                                "/ark.v1.ArkService/RegisterIntent" => {
                                    match behavior {
                                        Behavior::DelayRegistration(delay) => {
                                            tokio::time::sleep(delay).await;
                                        }
                                        Behavior::StallRegistration => {
                                            std::future::pending::<()>().await;
                                        }
                                        Behavior::StallStream
                                        | Behavior::StallInfo
                                        | Behavior::StallSubmit
                                        | Behavior::StallFinalize
                                        | Behavior::AcceptSpend
                                        | Behavior::RejectSubmit
                                        | Behavior::AcceptWithoutCosigning
                                        | Behavior::AcceptCosignedBy(_) => {}
                                    }
                                    RegisterIntentResponse {
                                        intent_id: "test-intent".to_owned(),
                                    }
                                    .encode_to_vec()
                                }
                                "/ark.v1.ArkService/GetEventStream" => {
                                    stream_observed.store(true, Ordering::SeqCst);
                                    if matches!(behavior, Behavior::StallStream) {
                                        let headers = http::Response::builder()
                                            .header("content-type", "application/grpc")
                                            .body(())
                                            .unwrap();
                                        let _stream =
                                            response.send_response(headers, false).unwrap();
                                        std::future::pending::<()>().await;
                                    }
                                    // Reaching this response proves the refresh survived the
                                    // registration delay and progressed to the next RPC.
                                    let headers = http::Response::builder()
                                        .header("content-type", "application/grpc")
                                        .header("grpc-status", "9")
                                        .header("grpc-message", "refresh reached event stream")
                                        .body(())
                                        .unwrap();
                                    let _ = response.send_response(headers, true);
                                    return;
                                }
                                path => panic!("unexpected request: {path}"),
                            };
                            let headers = http::Response::builder()
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
                            let Ok(mut stream) = response.send_response(headers, false) else {
                                return;
                            };
                            let mut frame = BytesMut::with_capacity(5 + payload.len());
                            frame.put_u8(0); // Uncompressed gRPC message.
                            frame.put_u32(payload.len() as u32);
                            frame.extend_from_slice(&payload);
                            if stream.send_data(Bytes::from(frame), false).is_ok() {
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", "0".parse().unwrap());
                                let _ = stream.send_trailers(trailers);
                            }
                        });
                    }
                });
            }
        });
        Self {
            url,
            stream_requested,
            submit_requests,
            finalize_requests,
            submitted_checkpoint_sigs,
            task,
        }
    }
}

/// `GetInfoResponse.deprecated_signers` (field 17). The generated proto type
/// is private to ark-grpc, so the field is encoded separately and appended
/// to the info bytes; protobuf merges concatenated messages.
#[derive(Message)]
struct DeprecatedSigners {
    #[prost(message, repeated, tag = "17")]
    deprecated_signers: Vec<DeprecatedSigner>,
}

#[derive(Message)]
struct DeprecatedSigner {
    #[prost(string, tag = "1")]
    pubkey: String,
    #[prost(int64, tag = "2")]
    cutoff_date: i64,
}

fn server_info_bytes() -> Vec<u8> {
    let mut bytes = server_info().encode_to_vec();
    bytes.extend(
        DeprecatedSigners {
            deprecated_signers: vec![DeprecatedSigner {
                pubkey: keypair(DEPRECATED_SIGNER_SEED).public_key().to_string(),
                cutoff_date: i64::MAX,
            }],
        }
        .encode_to_vec(),
    );
    bytes
}

fn server_info() -> GetInfoResponse {
    let secp = Secp256k1::new();
    let key = server_keypair();
    GetInfoResponse {
        version: "test".to_owned(),
        signer_pubkey: key.public_key().to_string(),
        forfeit_pubkey: key.public_key().to_string(),
        forfeit_address: bitcoin::Address::p2tr(
            &secp,
            key.x_only_public_key().0,
            None,
            bitcoin::Network::Regtest,
        )
        .to_string(),
        network: "regtest".to_owned(),
        session_duration: 30,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 512,
        utxo_max_amount: -1,
        vtxo_max_amount: -1,
        dust: 330,
        digest: "test-digest".to_owned(),
        ..Default::default()
    }
}
