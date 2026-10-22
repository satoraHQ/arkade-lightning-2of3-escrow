//! Refresh recoverable escrow VTXOs back into the same escrow contract.
//!
//! Refreshing is the recovery path for escrow VTXOs that are no longer
//! spendable via the normal offchain path. A refresh settles one or more
//! recoverable escrow VTXOs into a single new VTXO at the active-signer escrow
//! address. Once that new VTXO is spendable, callers should use the normal
//! offchain flow.

use anyhow::{Context, Result};
use ark_core::batch::{self, Delegate};
use ark_core::intent;
use ark_core::server;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1, schnorr};
use bitcoin::{Amount, OutPoint, Psbt, Txid, XOnlyPublicKey};
use rand::{CryptoRng, Rng};

use crate::contract::{EscrowContract, SignerSet};

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
/// selected signer set before
/// calling [`execute_refresh`] or [`crate::client::EscrowClient::refresh_escrow`].
#[derive(Debug, Clone)]
pub struct RefreshIntent {
    pub intent: intent::Intent,
    pub forfeit_psbts: Vec<Psbt>,
    pub refresh_cosigner_pk: secp256k1::PublicKey,
    /// A `delete` intent over the same inputs, signed by the same parties.
    ///
    /// Used to clear a queued intent left behind by an earlier attempt that
    /// never joined a batch (the server answers "already registered" at
    /// registration), and to withdraw this attempt's own intent if the
    /// ceremony fails or times out. Its `expire_at` is 0, so it stays valid
    /// until used. `None` for callers that have not adopted it; then stale
    /// intents are left for the server to drop.
    pub delete_intent: Option<intent::Intent>,
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
            delete_intent: None,
        }
    }
}

/// Build the unsigned `delete` intent proof for `intent_inputs`.
fn prepare_delete_intent(intent_inputs: Vec<intent::Input>) -> Result<intent::Intent> {
    // `make_intent` decorates and signs in one go; signing closures that
    // return nothing leave an unsigned but fully decorated proof, which
    // `sign_refresh` then signs the same way as the register proof.
    intent::make_intent(
        |_, _| Ok(vec![]),
        |_, _| {
            Err(ark_core::Error::ad_hoc(
                "escrow intents have no onchain inputs",
            ))
        },
        intent_inputs,
        vec![],
        intent::IntentMessage::Delete { expire_at: 0 },
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("preparing delete intent")
}

/// Whether a registration error means an earlier intent still holds one of
/// the inputs.
pub fn is_stale_intent_error(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("already registered")
}

/// Whether a delete error means there was nothing queued to delete.
pub fn is_no_matching_intent_error(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("no matching intents")
}

pub(crate) struct RefreshInput<'a> {
    pub contract: &'a EscrowContract,
    pub vtxo: &'a RefreshVtxo,
}

/// Prepare unsigned refresh PSBTs.
///
/// The refresh consumes one or more recoverable escrow VTXOs and creates a
/// single offchain output for the full input sum. If the Arkade signer has
/// rotated, inputs are spent from `contract` while the output is created at the
/// same escrow template using the current `server_info.signer_pk`.
/// No final destination or fee outputs are included here; callers
/// should perform the normal offchain signer-set spend after the refreshed VTXO
/// becomes spendable.
pub fn prepare_refresh(
    contract: &EscrowContract,
    vtxos: &[RefreshVtxo],
    signer_set: SignerSet,
    refresh_cosigner_pk: secp256k1::PublicKey,
    server_info: &server::Info,
) -> Result<RefreshIntent> {
    let inputs = vtxos
        .iter()
        .map(|vtxo| RefreshInput { contract, vtxo })
        .collect::<Vec<_>>();

    prepare_refresh_resolved(
        contract,
        &inputs,
        signer_set,
        refresh_cosigner_pk,
        server_info,
    )
}

pub(crate) fn prepare_refresh_resolved(
    output_template_contract: &EscrowContract,
    inputs: &[RefreshInput<'_>],
    signer_set: SignerSet,
    refresh_cosigner_pk: secp256k1::PublicKey,
    server_info: &server::Info,
) -> Result<RefreshIntent> {
    let intent_inputs = build_intent_inputs(inputs, signer_set)?;

    let total_escrow_amount: Amount = inputs.iter().map(|input| input.vtxo.amount).sum();
    let active_server: XOnlyPublicKey = server_info.signer_pk.into();
    let output_contract = output_template_contract.with_server(active_server)?;
    let outputs = vec![intent::Output::Offchain(bitcoin::TxOut {
        script_pubkey: output_contract.address().to_p2tr_script_pubkey(),
        value: total_escrow_amount,
    })];

    let delete_intent = prepare_delete_intent(intent_inputs.clone())?;
    let delegate = batch::prepare_delegate_psbts(
        intent_inputs,
        outputs,
        refresh_cosigner_pk,
        &server_info.forfeit_address,
        server_info.dust,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("preparing refresh PSBTs")?;

    let mut refresh = RefreshIntent::from_delegate(delegate);
    refresh.delete_intent = Some(delete_intent);
    Ok(refresh)
}

/// Sign refresh PSBTs (intent proof, forfeits and, if present, the delete
/// intent proof) with a single keypair.
pub fn sign_refresh(refresh: &mut RefreshIntent, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;
    let sign_fn = |_: &mut bitcoin::psbt::Input,
                   msg: secp256k1::Message|
     -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
        let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
        Ok(vec![(sig, xonly)])
    };

    batch::sign_delegate_psbts(
        sign_fn,
        &mut refresh.intent.proof,
        &mut refresh.forfeit_psbts,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("signing refresh PSBTs")?;
    if let Some(delete) = refresh.delete_intent.as_mut() {
        sign_delete_intent_proof(&mut delete.proof, keypair)?;
    }
    Ok(())
}

/// Sign a `delete` intent proof with a single keypair.
pub fn sign_delete_intent_proof(proof: &mut Psbt, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;
    batch::sign_delegate_psbts(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        proof,
        &mut [],
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("signing delete intent proof")
}

/// Ask the server to drop every queued intent that spends an input of
/// `delete_intent`. Succeeds when nothing was queued.
pub async fn delete_intent(grpc: &ark_grpc::Client, delete_intent: intent::Intent) -> Result<()> {
    match grpc.delete_intent(delete_intent).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let e = anyhow::anyhow!("{e:#}");
            if is_no_matching_intent_error(&e) {
                tracing::debug!("No queued intent to delete");
                Ok(())
            } else {
                Err(e.context("deleting intent"))
            }
        }
    }
}

/// Execute a signed refresh intent via the Arkade batch ceremony.
///
/// If registration fails because an earlier attempt's intent still holds an
/// input and `refresh.delete_intent` is present, that intent is deleted and
/// registration retried once. The caller is expected to delete this
/// attempt's intent if the ceremony fails afterwards; see
/// [`crate::client::EscrowClient::refresh_escrow`].
pub async fn execute_refresh<R: Rng + CryptoRng>(
    grpc: &ark_grpc::Client,
    server_info: &server::Info,
    rng: &mut R,
    refresh: RefreshIntent,
    refresh_cosigner_kp: Keypair,
) -> Result<Txid> {
    let delete = refresh.delete_intent.clone();
    let retry = refresh.clone();
    #[allow(deprecated)]
    let first = crate::delegate::settle_delegate(
        grpc,
        server_info,
        rng,
        refresh.into_delegate(),
        refresh_cosigner_kp,
    )
    .await;
    match (first, delete) {
        (Err(e), Some(delete)) if is_stale_intent_error(&e) => {
            tracing::warn!(
                error = %e,
                "An input is held by a stale intent; deleting it and retrying registration"
            );
            delete_intent(grpc, delete)
                .await
                .context("deleting the stale intent holding the refresh inputs")?;
            #[allow(deprecated)]
            crate::delegate::settle_delegate(
                grpc,
                server_info,
                rng,
                retry.into_delegate(),
                refresh_cosigner_kp,
            )
            .await
        }
        (result, _) => result,
    }
}

fn build_intent_inputs(
    inputs: &[RefreshInput<'_>],
    signer_set: SignerSet,
) -> Result<Vec<intent::Input>> {
    inputs
        .iter()
        .map(|input| {
            let spend_script = signer_set.script(input.contract.options());
            let control_block = input.contract.control_block(&spend_script)?;

            Ok(intent::Input::new(
                input.vtxo.outpoint,
                bitcoin::Sequence::ZERO,
                None,
                bitcoin::TxOut {
                    value: input.vtxo.amount,
                    script_pubkey: input.contract.script_pubkey(),
                },
                input.contract.tapscripts(),
                (spend_script, control_block),
                false,
                input.vtxo.is_swept,
                Vec::new(),
            ))
        })
        .collect()
}
