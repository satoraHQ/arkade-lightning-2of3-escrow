use std::sync::Mutex;

use ark_escrow::client::EscrowClient;
use ark_escrow::contract::{EscrowContract, EscrowOptions, SignerSet};
use ark_escrow::refresh::{self, RefreshIntent, RefreshVtxo};
use ark_escrow::spend_store::{FileSpendStore, PendingSpend, SpendStore};
use ark_escrow::{FeeOutput, ReleaseMode, plan_release, spend};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Amount, Network, Psbt, XOnlyPublicKey};
use magnus::prelude::*;
use magnus::value::Opaque;
use magnus::{Error, Ruby, function, method};
use tokio::runtime::Runtime;

// --- helpers ---

fn to_magnus_err(e: impl std::fmt::Display) -> Error {
    #[allow(deprecated)]
    // Use debug formatting to get the full anyhow error chain
    Error::new(magnus::exception::runtime_error(), format!("{e:#}"))
}

fn hex_to_32_bytes(hex: &str) -> Result<[u8; 32], Error> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(to_magnus_err(format!(
            "expected 64 hex chars, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(to_magnus_err)?;
        out[i] = u8::from_str_radix(s, 16).map_err(to_magnus_err)?;
    }
    Ok(out)
}

fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, Error> {
    let bytes = hex_to_32_bytes(hex)?;
    XOnlyPublicKey::from_slice(&bytes).map_err(to_magnus_err)
}

fn parse_network(s: &str) -> Result<Network, Error> {
    match s {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(to_magnus_err(format!("unknown network: {s}"))),
    }
}

fn parse_secret_key(hex: &str) -> Result<Keypair, Error> {
    let secp = Secp256k1::new();
    let bytes = hex_to_32_bytes(hex)?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).map_err(to_magnus_err)?;
    Ok(Keypair::from_secret_key(&secp, &sk))
}

fn psbt_to_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(psbt.serialize())
}

fn psbt_from_base64(s: &str) -> Result<Psbt, Error> {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    let bytes = STANDARD.decode(s).map_err(to_magnus_err)?;
    Psbt::deserialize(&bytes).map_err(to_magnus_err)
}

fn parse_signer_set(signer_set: &str) -> Result<SignerSet, Error> {
    match signer_set {
        "buyer_arbiter" => Ok(SignerSet::BuyerArbiter),
        "seller_arbiter" => Ok(SignerSet::SellerArbiter),
        "seller_buyer" => Ok(SignerSet::SellerBuyer),
        _ => Err(to_magnus_err(format!(
            "unknown signer_set: {signer_set}; expected 'buyer_arbiter', 'seller_arbiter', or 'seller_buyer'"
        ))),
    }
}

fn warn_deprecated(message: &str) {
    match Ruby::get() {
        Ok(ruby) => ruby.warning(message),
        Err(_) => eprintln!("warning: {message}"),
    }
}

fn parse_fee_outputs(fee_outputs: Vec<(String, u64)>) -> Result<Vec<FeeOutput>, Error> {
    fee_outputs
        .iter()
        .map(|(address, amount)| {
            let address = address.parse()?;
            Ok::<_, ark_core::Error>(FeeOutput {
                address,
                amount: Amount::from_sat(*amount),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_magnus_err)
}

// --- Callback-based SpendStore ---

/// A [`SpendStore`] that delegates to a Ruby object responding to
/// `save(id, json)`, `load(id) -> json|nil`, and `remove(id)`.
///
/// Uses [`Opaque`] so the Ruby value can be stored in a `Send + Sync` struct.
struct CallbackSpendStore {
    /// The Ruby object wrapped in `Opaque` for thread-safety.
    rb_store: Opaque<magnus::Value>,
}

impl CallbackSpendStore {
    fn new(rb_store: magnus::Value) -> Self {
        Self {
            rb_store: Opaque::from(rb_store),
        }
    }
}

impl SpendStore for CallbackSpendStore {
    fn save(&self, spend: &PendingSpend) -> anyhow::Result<()> {
        let ruby = Ruby::get().expect("called from Ruby thread");
        let store = ruby.get_inner(self.rb_store);
        let json = serde_json::to_string(spend)?;
        let _: magnus::Value = store
            .funcall("save", (spend.id.as_str(), json.as_str()))
            .map_err(|e| anyhow::anyhow!("Ruby store#save failed: {e}"))?;
        Ok(())
    }

    fn load(&self, id: &str) -> anyhow::Result<Option<PendingSpend>> {
        let ruby = Ruby::get().expect("called from Ruby thread");
        let store = ruby.get_inner(self.rb_store);
        let result: Option<String> = store
            .funcall("load", (id,))
            .map_err(|e| anyhow::anyhow!("Ruby store#load failed: {e}"))?;
        match result {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    fn remove(&self, id: &str) -> anyhow::Result<()> {
        let ruby = Ruby::get().expect("called from Ruby thread");
        let store = ruby.get_inner(self.rb_store);
        let _: magnus::Value = store
            .funcall("remove", (id,))
            .map_err(|e| anyhow::anyhow!("Ruby store#remove failed: {e}"))?;
        Ok(())
    }
}

// --- Ruby wrappers ---

/// Ruby class: `ArkEscrow::Contract`
#[magnus::wrap(class = "ArkEscrow::Contract")]
struct RbContract {
    inner: EscrowContract,
}

impl RbContract {
    fn new(
        seller_pk: String,
        buyer_pk: String,
        arbiter_pk: String,
        server_pk: String,
        unilateral_exit_delay: u32,
        network: String,
    ) -> Result<Self, Error> {
        let opts = EscrowOptions {
            seller: parse_xonly(&seller_pk)?,
            buyer: parse_xonly(&buyer_pk)?,
            arbiter: parse_xonly(&arbiter_pk)?,
            server: parse_xonly(&server_pk)?,
            // Match Arkade's parse_sequence_number convention:
            // values < 512 → block-based, values >= 512 → seconds-based
            unilateral_exit_delay: if unilateral_exit_delay < 512 {
                bitcoin::Sequence::from_height(unilateral_exit_delay as u16)
            } else {
                bitcoin::Sequence::from_seconds_ceil(unilateral_exit_delay)
                    .map_err(to_magnus_err)?
            },
        };
        let net = parse_network(&network)?;
        let contract = EscrowContract::new(opts, net).map_err(to_magnus_err)?;
        Ok(Self { inner: contract })
    }

    fn address(&self) -> String {
        self.inner.address().to_string()
    }
}

/// Ruby class: `ArkEscrow::Client`
///
/// Uses a persistent tokio runtime so the gRPC connection stays alive
/// across calls (a new runtime per call would invalidate the channel).
#[magnus::wrap(class = "ArkEscrow::Client")]
struct RbClient {
    inner: Mutex<EscrowClient>,
    store: Box<dyn SpendStore + Send + Sync>,
    rt: Runtime,
}

impl RbClient {
    /// Create a client with file-based crash-recovery storage.
    ///
    /// - `url`: Arkade gRPC URL.
    /// - `store_dir`: directory for persisting pending spends.
    fn with_file_store(url: String, store_dir: String) -> Result<Self, Error> {
        let rt = Runtime::new().map_err(to_magnus_err)?;
        let store = FileSpendStore::new(&store_dir).map_err(to_magnus_err)?;
        Ok(Self {
            inner: Mutex::new(EscrowClient::new(&url)),
            store: Box::new(store),
            rt,
        })
    }

    /// Create a client with a custom Ruby store object for crash recovery.
    ///
    /// The store object must respond to:
    /// - `save(id, json)` — persist a pending spend as JSON.
    /// - `load(id) -> json|nil` — load a pending spend by ID.
    /// - `remove(id)` — delete a pending spend after finalization.
    ///
    /// For now, callers may also rely on this store to infer whether an
    /// offchain escrow spend is already pending for a given application-level
    /// ID. Long-term, Arkade should surface pending spend status for escrow
    /// VTXOs explicitly so callers do not need to approximate that via the
    /// local crash-recovery store.
    fn with_custom_store(url: String, rb_store: magnus::Value) -> Result<Self, Error> {
        let rt = Runtime::new().map_err(to_magnus_err)?;
        let store = CallbackSpendStore::new(rb_store);
        Ok(Self {
            inner: Mutex::new(EscrowClient::new(&url)),
            store: Box::new(store),
            rt,
        })
    }

    fn connect(&self) -> Result<(), Error> {
        let mut client = self.inner.lock().map_err(to_magnus_err)?;
        self.rt.block_on(client.connect()).map_err(to_magnus_err)?;
        Ok(())
    }

    fn server_pk(&self) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;
        Ok(bitcoin::hex::DisplayHex::to_lower_hex_string(
            &info.signer_pk.x_only_public_key().0.serialize(),
        ))
    }

    fn unilateral_exit_delay(&self) -> Result<u32, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;
        Ok(info.unilateral_exit_delay.to_consensus_u32())
    }

    /// Find the escrow VTXO. Returns [outpoint_str, amount_sats] or nil.
    fn find_escrow_vtxo(&self, contract: &RbContract) -> Result<Option<(String, u64)>, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let vtxo = self
            .rt
            .block_on(client.find_escrow_vtxo(&contract.inner))
            .map_err(to_magnus_err)?;
        Ok(vtxo.map(|v| (v.outpoint.to_string(), v.amount.to_sat())))
    }

    /// Find all unspent escrow VTXOs and check recoverability.
    ///
    /// Returns `[vtxos_array, any_recoverable]` where vtxos_array is
    /// `[[outpoint, amount_sats, is_swept], ...]`.
    ///
    /// Note: this only reflects Arkade-visible VTXO state today. Pending
    /// offchain spend status is currently inferred separately from the local
    /// [`SpendStore`] until Arkade surfaces that status explicitly.
    #[allow(clippy::type_complexity)]
    fn find_refresh_vtxos(
        &self,
        contract: &RbContract,
    ) -> Result<(Vec<(String, u64, bool)>, bool), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let (vtxos, any_recoverable) = self
            .rt
            .block_on(client.find_refresh_vtxos(&contract.inner))
            .map_err(to_magnus_err)?;
        let vtxo_data: Vec<(String, u64, bool)> = vtxos
            .iter()
            .map(|v| (v.outpoint.to_string(), v.amount.to_sat(), v.is_swept))
            .collect();
        Ok((vtxo_data, any_recoverable))
    }

    /// Find all unspent escrow VTXOs and check recoverability.
    #[allow(clippy::type_complexity)]
    #[allow(deprecated)]
    fn find_escrow_vtxos(
        &self,
        contract: &RbContract,
    ) -> Result<(Vec<(String, u64, bool)>, bool), Error> {
        self.find_refresh_vtxos(contract)
    }

    /// Get escrow VTXO status for control-flow decisions.
    ///
    /// Returns `[pending_offchain, vtxos_array, any_recoverable]` where:
    /// - `pending_offchain` is true if the local [`SpendStore`] has a pending
    ///   offchain spend for `id`
    /// - `vtxos_array` is `[[outpoint, amount_sats, is_swept], ...]`
    /// - `any_recoverable` indicates whether any escrow VTXO has entered the
    ///   recoverable path
    ///
    /// For now, `pending_offchain` is inferred from the local spend store.
    /// Once Arkade exposes pending spend status explicitly for escrow VTXOs,
    /// this method should source that signal from Arkade instead.
    #[allow(clippy::type_complexity)]
    #[allow(deprecated)]
    fn get_escrow_vtxo_status(
        &self,
        id: String,
        contract: &RbContract,
    ) -> Result<(bool, Vec<(String, u64, bool)>, bool), Error> {
        let pending_offchain = self.store.load(&id).map_err(to_magnus_err)?.is_some();
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let (vtxos, any_recoverable) = self
            .rt
            .block_on(client.find_refresh_vtxos(&contract.inner))
            .map_err(to_magnus_err)?;
        let vtxo_data: Vec<(String, u64, bool)> = vtxos
            .iter()
            .map(|v| (v.outpoint.to_string(), v.amount.to_sat(), v.is_swept))
            .collect();
        Ok((pending_offchain, vtxo_data, any_recoverable))
    }

    /// Quote a release without building PSBTs.
    ///
    /// Returns `[buyer_amount_sats, effective_fee_outputs, discarded_fee_outputs]`
    /// where each fee-output array contains `[address, amount_sats]` tuples.
    #[allow(clippy::type_complexity)]
    fn quote_release(
        &self,
        escrow_amount_sats: u64,
        fee_outputs: Vec<(String, u64)>,
        use_delegate: bool,
    ) -> Result<(u64, Vec<(String, u64)>, Vec<(String, u64)>), Error> {
        if use_delegate {
            warn_deprecated(
                "ArkEscrow: quote_release(..., use_delegate: true) is legacy; refresh first, then quote/build the normal offchain release",
            );
        }
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;
        let fee_outputs = parse_fee_outputs(fee_outputs)?;
        let release_plan = plan_release(
            Amount::from_sat(escrow_amount_sats),
            &fee_outputs,
            if use_delegate {
                ReleaseMode::Delegate
            } else {
                ReleaseMode::Offchain
            },
            info.dust,
        )
        .map_err(to_magnus_err)?;

        let effective_fee_outputs = release_plan
            .effective_fee_outputs
            .iter()
            .map(|o| (o.address.to_string(), o.amount.to_sat()))
            .collect();
        let discarded_fee_outputs = release_plan
            .discarded_fee_outputs
            .iter()
            .map(|o| (o.address.to_string(), o.amount.to_sat()))
            .collect();

        Ok((
            release_plan.buyer_amount.to_sat(),
            effective_fee_outputs,
            discarded_fee_outputs,
        ))
    }

    /// Prepare unsigned refresh PSBTs.
    ///
    /// Returns `[intent_proof_b64, intent_message_json, forfeit_psbts_b64[], cosigner_pk_hex]`.
    fn prepare_refresh(
        &self,
        contract: &RbContract,
        vtxos_data: Vec<(String, u64, bool)>,
        signer_set: String,
        cosigner_sk_hex: String,
    ) -> Result<(String, String, Vec<String>, String), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let vtxos: Vec<RefreshVtxo> = vtxos_data
            .into_iter()
            .map(|(outpoint_str, amount_sats, is_swept)| {
                let outpoint: bitcoin::OutPoint = outpoint_str.parse().map_err(to_magnus_err)?;
                Ok(RefreshVtxo {
                    outpoint,
                    amount: Amount::from_sat(amount_sats),
                    is_swept,
                })
            })
            .collect::<Result<_, Error>>()?;

        let signer_set = parse_signer_set(&signer_set)?;
        let cosigner_kp = parse_secret_key(&cosigner_sk_hex)?;
        let cosigner_pk = cosigner_kp.public_key();

        let refresh =
            refresh::prepare_refresh(&contract.inner, &vtxos, signer_set, cosigner_pk, info)
                .map_err(to_magnus_err)?;

        let intent_proof_b64 = psbt_to_base64(&refresh.intent.proof);
        let intent_message_json = refresh.intent.serialize_message().map_err(to_magnus_err)?;
        let forfeit_psbts_b64: Vec<String> =
            refresh.forfeit_psbts.iter().map(psbt_to_base64).collect();
        let cosigner_pk_hex =
            bitcoin::hex::DisplayHex::to_lower_hex_string(&refresh.refresh_cosigner_pk.serialize());

        Ok((
            intent_proof_b64,
            intent_message_json,
            forfeit_psbts_b64,
            cosigner_pk_hex,
        ))
    }

    /// Refresh the escrow contract. Blocks until the batch ceremony completes.
    ///
    /// Takes the fully-signed refresh PSBTs and returns the commitment
    /// transaction ID (hex string).
    fn refresh_escrow(
        &self,
        intent_proof_b64: String,
        intent_message_json: String,
        forfeit_psbts_b64: Vec<String>,
        cosigner_sk_hex: String,
    ) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;

        let intent_proof = psbt_from_base64(&intent_proof_b64)?;
        let intent_message: ark_core::intent::IntentMessage =
            serde_json::from_str(&intent_message_json).map_err(to_magnus_err)?;
        let forfeit_psbts: Vec<Psbt> = forfeit_psbts_b64
            .iter()
            .map(|b| psbt_from_base64(b))
            .collect::<Result<_, _>>()?;

        let cosigner_kp = parse_secret_key(&cosigner_sk_hex)?;

        let refresh = RefreshIntent {
            intent: ark_core::intent::Intent::new(intent_proof, intent_message),
            forfeit_psbts,
            refresh_cosigner_pk: cosigner_kp.public_key(),
        };

        let txid = self
            .rt
            .block_on(client.refresh_escrow(refresh, cosigner_kp))
            .map_err(to_magnus_err)?;

        Ok(txid.to_string())
    }

    /// Execute delegate settlement. Blocks until the batch ceremony completes.
    ///
    /// Deprecated: use `refresh_escrow` for recoverable escrow VTXOs, then the
    /// normal offchain signer-set flow.
    ///
    /// Takes the fully-signed delegate PSBTs and runs the Arkade batch.
    /// Returns the commitment transaction ID (hex string).
    #[allow(deprecated)]
    fn settle_delegate(
        &self,
        intent_proof_b64: String,
        intent_message_json: String,
        forfeit_psbts_b64: Vec<String>,
        cosigner_sk_hex: String,
    ) -> Result<String, Error> {
        warn_deprecated(
            "ArkEscrow: settle_delegate is deprecated; use refresh_escrow for recoverable escrow VTXOs",
        );
        let client = self.inner.lock().map_err(to_magnus_err)?;

        let intent_proof = psbt_from_base64(&intent_proof_b64)?;
        let intent_message: ark_core::intent::IntentMessage =
            serde_json::from_str(&intent_message_json).map_err(to_magnus_err)?;
        let forfeit_psbts: Vec<Psbt> = forfeit_psbts_b64
            .iter()
            .map(|b| psbt_from_base64(b))
            .collect::<Result<_, _>>()?;

        let cosigner_kp = parse_secret_key(&cosigner_sk_hex)?;

        let delegate = ark_core::batch::Delegate {
            intent: ark_core::intent::Intent::new(intent_proof, intent_message),
            forfeit_psbts,
            delegate_cosigner_pk: cosigner_kp.public_key(),
        };

        let txid = self
            .rt
            .block_on(client.settle_delegate(delegate, cosigner_kp))
            .map_err(to_magnus_err)?;

        Ok(txid.to_string())
    }

    /// Build a release transaction. Returns the ark_tx PSBT (base64) and
    /// checkpoint PSBTs (array of base64).
    fn build_release(
        &self,
        contract: &RbContract,
        escrow_outpoint: String,
        escrow_amount_sats: u64,
        buyer_dest_address: String,
        fee_outputs: Vec<(String, u64)>,
        signer_set: String,
    ) -> Result<(String, Vec<String>), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let outpoint: bitcoin::OutPoint = escrow_outpoint.parse().map_err(to_magnus_err)?;
        let escrow_vtxo = spend::EscrowVtxo {
            outpoint,
            amount: Amount::from_sat(escrow_amount_sats),
        };

        let buyer_dest: ark_core::ArkAddress = buyer_dest_address.parse().map_err(to_magnus_err)?;
        let fee_outputs = parse_fee_outputs(fee_outputs)?;
        let signer_set = parse_signer_set(&signer_set)?;

        let release = spend::build_release_tx(
            &contract.inner,
            &escrow_vtxo,
            &buyer_dest,
            &fee_outputs,
            signer_set,
            info,
        )
        .map_err(to_magnus_err)?;

        let ark_tx_b64 = psbt_to_base64(&release.ark_tx);
        let checkpoints_b64: Vec<String> =
            release.checkpoint_txs.iter().map(psbt_to_base64).collect();

        Ok((ark_tx_b64, checkpoints_b64))
    }

    /// Build a refund transaction. Returns the ark_tx PSBT (base64) and
    /// checkpoint PSBTs (array of base64).
    fn build_refund(
        &self,
        contract: &RbContract,
        escrow_outpoint: String,
        escrow_amount_sats: u64,
        seller_dest_address: String,
        signer_set: String,
    ) -> Result<(String, Vec<String>), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let outpoint: bitcoin::OutPoint = escrow_outpoint.parse().map_err(to_magnus_err)?;
        let escrow_vtxo = spend::EscrowVtxo {
            outpoint,
            amount: Amount::from_sat(escrow_amount_sats),
        };

        let seller_dest: ark_core::ArkAddress =
            seller_dest_address.parse().map_err(to_magnus_err)?;
        let signer_set = parse_signer_set(&signer_set)?;

        let refund = spend::build_refund_tx(
            &contract.inner,
            &escrow_vtxo,
            &seller_dest,
            signer_set,
            info,
        )
        .map_err(to_magnus_err)?;

        let ark_tx_b64 = psbt_to_base64(&refund.ark_tx);
        let checkpoints_b64: Vec<String> =
            refund.checkpoint_txs.iter().map(psbt_to_base64).collect();

        Ok((ark_tx_b64, checkpoints_b64))
    }

    /// Spend an escrow VTXO offchain with crash recovery.
    ///
    /// Wraps the two-phase Arkade protocol (submit + finalize) with a
    /// persistence guard.
    ///
    /// - `id` — unique identifier for deduplication (e.g. trade ID).
    /// - `merged_ark_tx_b64` — ark_tx PSBT with all non-server sigs merged.
    /// - `unsigned_checkpoint_txs_b64` — raw unsigned checkpoint PSBTs.
    /// - `party_signed_checkpoints_b64` — array of arrays: each inner array is
    ///   one party's signed checkpoint PSBTs (base64).
    ///
    /// Returns the Arkade transaction ID (hex string).
    fn spend_escrow_offchain(
        &self,
        id: String,
        merged_ark_tx_b64: String,
        unsigned_checkpoint_txs_b64: Vec<String>,
        party_signed_checkpoints_b64: Vec<Vec<String>>,
    ) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;

        let merged_ark_tx = psbt_from_base64(&merged_ark_tx_b64)?;
        let unsigned_checkpoints: Vec<Psbt> = unsigned_checkpoint_txs_b64
            .iter()
            .map(|b| psbt_from_base64(b))
            .collect::<Result<_, _>>()?;

        let party_checkpoints: Vec<Vec<Psbt>> = party_signed_checkpoints_b64
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|b| psbt_from_base64(b))
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?;

        let party_refs: Vec<&[Psbt]> = party_checkpoints.iter().map(|v| v.as_slice()).collect();

        let txid = self
            .rt
            .block_on(client.spend_escrow_offchain(
                &*self.store,
                &id,
                merged_ark_tx,
                unsigned_checkpoints,
                &party_refs,
            ))
            .map_err(to_magnus_err)?;

        Ok(txid.to_string())
    }
}

// --- Signing helpers (stateless, exposed as module functions) ---

fn rb_sign_ark_tx(psbt_b64: String, secret_key_hex: String) -> Result<String, Error> {
    let mut psbt = psbt_from_base64(&psbt_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    spend::sign_ark_tx(&mut psbt, &kp).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&psbt))
}

fn rb_sign_checkpoint(psbt_b64: String, secret_key_hex: String) -> Result<String, Error> {
    let mut psbt = psbt_from_base64(&psbt_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    spend::sign_checkpoint(&mut psbt, &kp).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&psbt))
}

/// Sign refresh PSBTs (intent + forfeits) with a single keypair.
/// Takes and returns: (intent_proof_b64, forfeit_psbts_b64[])
fn rb_sign_refresh(
    intent_proof_b64: String,
    forfeit_psbts_b64: Vec<String>,
    secret_key_hex: String,
) -> Result<(String, Vec<String>), Error> {
    sign_intent_and_forfeits(intent_proof_b64, forfeit_psbts_b64, secret_key_hex)
}

/// Sign delegate PSBTs (intent + forfeits) with a single keypair.
/// Takes and returns: (intent_proof_b64, forfeit_psbts_b64[])
fn rb_sign_delegate(
    intent_proof_b64: String,
    forfeit_psbts_b64: Vec<String>,
    secret_key_hex: String,
) -> Result<(String, Vec<String>), Error> {
    warn_deprecated("ArkEscrow: sign_delegate is deprecated; use sign_refresh");
    sign_intent_and_forfeits(intent_proof_b64, forfeit_psbts_b64, secret_key_hex)
}

fn sign_intent_and_forfeits(
    intent_proof_b64: String,
    forfeit_psbts_b64: Vec<String>,
    secret_key_hex: String,
) -> Result<(String, Vec<String>), Error> {
    let intent_proof = psbt_from_base64(&intent_proof_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    let secp = Secp256k1::new();
    let xonly = kp.x_only_public_key().0;

    let mut signed_intent = intent_proof;
    let mut forfeit_psbts: Vec<Psbt> = forfeit_psbts_b64
        .iter()
        .map(|b| psbt_from_base64(b))
        .collect::<Result<_, _>>()?;

    // sign_delegate_psbts handles both intent (SIGHASH_ALL) and
    // forfeit (SIGHASH_ALL|ANYONECANPAY) inputs correctly.
    ark_core::batch::sign_delegate_psbts(
        |_,
         msg: secp256k1::Message|
         -> Result<
            Vec<(bitcoin::secp256k1::schnorr::Signature, XOnlyPublicKey)>,
            ark_core::Error,
        > {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            Ok(vec![(sig, xonly)])
        },
        &mut signed_intent,
        &mut forfeit_psbts,
    )
    .map_err(to_magnus_err)?;

    let intent_b64 = psbt_to_base64(&signed_intent);
    let forfeits_b64: Vec<String> = forfeit_psbts.iter().map(psbt_to_base64).collect();
    Ok((intent_b64, forfeits_b64))
}

fn rb_merge_sigs(base_b64: String, other_b64: String) -> Result<String, Error> {
    let mut base = psbt_from_base64(&base_b64)?;
    let other = psbt_from_base64(&other_b64)?;
    spend::merge_ark_tx_sigs(&mut base, &other).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&base))
}

// --- Init ---

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    // Init tracing so Rust logs are visible. Controlled by RUST_LOG env var.
    // e.g. RUST_LOG=ark_escrow=debug,ark_escrow_ruby=debug
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ark_escrow=info,ark_escrow_ruby=info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init()
        .ok();

    let module = ruby.define_module("ArkEscrow")?;

    let contract_class = module.define_class("Contract", ruby.class_object())?;
    contract_class.define_singleton_method("new", function!(RbContract::new, 6))?;
    contract_class.define_method("address", method!(RbContract::address, 0))?;

    let client_class = module.define_class("Client", ruby.class_object())?;
    client_class
        .define_singleton_method("with_file_store", function!(RbClient::with_file_store, 2))?;
    client_class.define_singleton_method(
        "with_custom_store",
        function!(RbClient::with_custom_store, 2),
    )?;
    client_class.define_method("connect", method!(RbClient::connect, 0))?;
    client_class.define_method("server_pk", method!(RbClient::server_pk, 0))?;
    client_class.define_method(
        "unilateral_exit_delay",
        method!(RbClient::unilateral_exit_delay, 0),
    )?;
    client_class.define_method("find_escrow_vtxo", method!(RbClient::find_escrow_vtxo, 1))?;
    client_class.define_method(
        "find_refresh_vtxos",
        method!(RbClient::find_refresh_vtxos, 1),
    )?;
    client_class.define_method("find_escrow_vtxos", method!(RbClient::find_escrow_vtxos, 1))?;
    client_class.define_method(
        "get_escrow_vtxo_status",
        method!(RbClient::get_escrow_vtxo_status, 2),
    )?;
    client_class.define_method("quote_release", method!(RbClient::quote_release, 3))?;
    client_class.define_method("build_release", method!(RbClient::build_release, 6))?;
    client_class.define_method("build_refund", method!(RbClient::build_refund, 5))?;
    client_class.define_method(
        "spend_escrow_offchain",
        method!(RbClient::spend_escrow_offchain, 4),
    )?;
    client_class.define_method("prepare_refresh", method!(RbClient::prepare_refresh, 4))?;
    client_class.define_method("refresh_escrow", method!(RbClient::refresh_escrow, 4))?;
    client_class.define_method("settle_delegate", method!(RbClient::settle_delegate, 4))?;

    module.define_module_function("sign_ark_tx", function!(rb_sign_ark_tx, 2))?;
    module.define_module_function("sign_checkpoint", function!(rb_sign_checkpoint, 2))?;
    module.define_module_function("merge_sigs", function!(rb_merge_sigs, 2))?;
    module.define_module_function("sign_refresh", function!(rb_sign_refresh, 3))?;
    module.define_module_function("sign_delegate", function!(rb_sign_delegate, 3))?;

    Ok(())
}
