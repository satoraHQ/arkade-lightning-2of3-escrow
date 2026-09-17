use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
        let info = server_info().encode_to_vec();
        let stream_requested = Arc::new(AtomicBool::new(false));
        let stream_observed = stream_requested.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let info = info.clone();
                let stream_observed = stream_observed.clone();
                connections.spawn(async move {
                    let mut connection = h2::server::handshake(socket).await.unwrap();
                    let mut requests = JoinSet::new();
                    while let Some(request) = connection.accept().await {
                        let (request, mut response) = request.unwrap();
                        let info = info.clone();
                        let stream_observed = stream_observed.clone();
                        requests.spawn(async move {
                            let payload = match request.uri().path() {
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
                                        Behavior::StallStream | Behavior::StallInfo => {}
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
            task,
        }
    }
}

fn server_info() -> GetInfoResponse {
    let secp = Secp256k1::new();
    let key = Keypair::from_seckey_slice(&secp, &[7; 32]).unwrap();
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
