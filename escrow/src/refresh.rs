//! Refresh recoverable escrow VTXOs back into the same escrow contract.
//!
//! Refreshing is the recovery path for escrow VTXOs that are no longer
//! spendable via the normal offchain path. A refresh settles one or more
//! recoverable escrow VTXOs into a single new VTXO at the same escrow address.
//! Once that new VTXO is spendable, callers should use the normal offchain
//! release/refund flow.

use anyhow::{Context, Result};
use ark_core::batch::{self, Delegate};
use ark_core::intent;
use ark_core::server;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1, schnorr};
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Txid, XOnlyPublicKey};
use rand::{CryptoRng, Rng};

use crate::contract::EscrowContract;

/// Business action that the refresh enables.
///
/// The refresh output is always sent back to the same escrow contract address;
/// this enum selects which collaborative escrow leaf must be signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshPath {
    /// Refresh using the Bob + arbiter + server leaf, then release offchain.
    Release,
    /// Refresh using the Alice + arbiter + server leaf, then refund offchain.
    Refund,
}

/// Everything needed to describe an escrow VTXO for refresh.
#[derive(Debug, Clone)]
pub struct RefreshVtxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub is_swept: bool,
}

/// Prepared refresh intent and forfeit PSBTs.
///
/// The intent proof and forfeit PSBTs must be signed by the selected escrow
/// leaf parties (arbiter + Bob for release, arbiter + Alice for refund) before
/// calling [`execute_refresh`] or [`crate::client::EscrowClient::refresh_escrow`].
#[derive(Debug, Clone)]
pub struct RefreshIntent {
    pub intent: intent::Intent,
    pub forfeit_psbts: Vec<Psbt>,
    pub refresh_cosigner_pk: secp256k1::PublicKey,
}

impl RefreshIntent {
    pub(crate) fn into_delegate(self) -> Delegate {
        Delegate {
            intent: self.intent,
            forfeit_psbts: self.forfeit_psbts,
            delegate_cosigner_pk: self.refresh_cosigner_pk,
        }
    }

    pub(crate) fn from_delegate(delegate: Delegate) -> Self {
        Self {
            intent: delegate.intent,
            forfeit_psbts: delegate.forfeit_psbts,
            refresh_cosigner_pk: delegate.delegate_cosigner_pk,
        }
    }
}

/// Prepare unsigned refresh PSBTs.
///
/// The refresh consumes one or more recoverable escrow VTXOs and creates a
/// single offchain output back to `contract.address()` for the full input sum.
/// No release/refund destination or fee outputs are included here; callers
/// should perform the normal offchain release/refund after the refreshed VTXO
/// becomes spendable.
pub fn prepare_refresh(
    contract: &EscrowContract,
    vtxos: &[RefreshVtxo],
    path: RefreshPath,
    refresh_cosigner_pk: secp256k1::PublicKey,
    server_info: &server::Info,
) -> Result<RefreshIntent> {
    let spend_script = match path {
        RefreshPath::Release => contract.options().bob_arbiter_script(),
        RefreshPath::Refund => contract.options().alice_arbiter_script(),
    };
    let control_block = contract.control_block(&spend_script)?;
    let tapscripts = contract.tapscripts();
    let script_pubkey = contract.script_pubkey();

    let intent_inputs = build_intent_inputs(
        vtxos,
        &spend_script,
        &control_block,
        &tapscripts,
        &script_pubkey,
    );

    let total_escrow_amount: Amount = vtxos.iter().map(|v| v.amount).sum();
    let outputs = vec![intent::Output::Offchain(bitcoin::TxOut {
        script_pubkey: contract.address().to_p2tr_script_pubkey(),
        value: total_escrow_amount,
    })];

    let delegate = batch::prepare_delegate_psbts(
        intent_inputs,
        outputs,
        refresh_cosigner_pk,
        &server_info.forfeit_address,
        server_info.dust,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("preparing refresh PSBTs")?;

    Ok(RefreshIntent::from_delegate(delegate))
}

/// Sign refresh PSBTs with a single keypair.
pub fn sign_refresh(refresh: &mut RefreshIntent, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    batch::sign_delegate_psbts(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        &mut refresh.intent.proof,
        &mut refresh.forfeit_psbts,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("signing refresh PSBTs")
}

/// Execute a signed refresh intent via the Arkade batch ceremony.
pub async fn execute_refresh<R: Rng + CryptoRng>(
    grpc: &ark_grpc::Client,
    server_info: &server::Info,
    rng: &mut R,
    refresh: RefreshIntent,
    refresh_cosigner_kp: Keypair,
) -> Result<Txid> {
    #[allow(deprecated)]
    crate::delegate::settle_delegate(
        grpc,
        server_info,
        rng,
        refresh.into_delegate(),
        refresh_cosigner_kp,
    )
    .await
}

fn build_intent_inputs(
    vtxos: &[RefreshVtxo],
    spend_script: &ScriptBuf,
    control_block: &bitcoin::taproot::ControlBlock,
    tapscripts: &[ScriptBuf],
    script_pubkey: &ScriptBuf,
) -> Vec<intent::Input> {
    vtxos
        .iter()
        .map(|vtxo| {
            intent::Input::new(
                vtxo.outpoint,
                bitcoin::Sequence::ZERO,
                None,
                bitcoin::TxOut {
                    value: vtxo.amount,
                    script_pubkey: script_pubkey.clone(),
                },
                tapscripts.to_vec(),
                (spend_script.clone(), control_block.clone()),
                false,
                vtxo.is_swept,
            )
        })
        .collect()
}
