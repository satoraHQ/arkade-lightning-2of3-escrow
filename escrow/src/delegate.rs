//! Legacy delegate settlement for escrow VTXOs.
//!
//! New code should use [`crate::refresh`] instead. Direct delegated release can
//! fail when fee/referral outputs are below Arkade's dust threshold. The
//! recommended flow is to refresh recoverable escrow VTXOs back into the same
//! escrow contract, then perform the normal offchain signer-set spend.
//!
//! When escrow VTXOs become recoverable (expired, swept, or dust), the normal
//! offchain spend path no longer works. Instead, the escrow can be settled via
//! an Arkade batch ceremony using the delegate pattern:
//!
//! 1. The arbiter prepares unsigned delegate PSBTs (intent + forfeits).
//! 2. The selected escrow leaf signers sign them.
//! 3. The delegate cosigner runs the batch.
//!
//! This module provides helpers for preparing, signing, and executing delegate
//! settlement of escrow VTXOs.

use std::collections::HashMap;

use anyhow::{Context, Result};
use ark_core::TxGraph;
use ark_core::batch::{
    self, Delegate, NonceKps, aggregate_nonces, complete_delegate_forfeit_txs, generate_nonce_tree,
    sign_batch_tree_tx,
};
use ark_core::intent;
use ark_core::server::{self, BatchTreeEventType, PartialSigTree, StreamEvent};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1, schnorr};
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
use rand::{CryptoRng, Rng};

use crate::contract::{EscrowContract, SignerSet};
use crate::{FeeOutput, ReleaseMode, plan_release};

/// Everything needed to describe an escrow VTXO for delegate settlement.
///
/// Unlike [`crate::spend::EscrowVtxo`] (which only needs outpoint + amount for
/// offchain spends), delegate settlement also needs to know whether the VTXO
/// has been swept (sub-dust VTXOs skip forfeits).
#[deprecated(note = "use refresh::RefreshVtxo")]
pub struct DelegateVtxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub is_swept: bool,
}

/// Prepare unsigned delegate PSBTs for a release using the selected signer set.
///
/// Returns a [`Delegate`] struct containing:
/// - An intent proof PSBT committing to the buyer destination output.
/// - Forfeit PSBTs (one per non-swept, non-dust VTXO) with SIGHASH_ALL|ANYONECANPAY.
///
/// The returned PSBTs are unsigned — callers sign with the selected escrow leaf
/// signers before handing off to the delegate cosigner for batch execution.
#[allow(deprecated)]
#[deprecated(
    note = "direct delegated release is legacy; use refresh::prepare_refresh(..., signer_set) followed by normal offchain spend"
)]
pub fn prepare_release_delegate(
    contract: &EscrowContract,
    vtxos: &[DelegateVtxo],
    buyer_dest: &ark_core::ArkAddress,
    fee_outputs: &[FeeOutput],
    signer_set: SignerSet,
    delegate_cosigner_pk: secp256k1::PublicKey,
    server_info: &server::Info,
) -> Result<Delegate> {
    let spend_script = signer_set.script(contract.options());
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
    let release_plan = plan_release(
        total_escrow_amount,
        fee_outputs,
        ReleaseMode::Delegate,
        server_info.dust,
    )?;

    for fee_output in &release_plan.discarded_fee_outputs {
        tracing::warn!(fee_output = ?fee_output, "Sub-dust fee output cannot be generated via settlement");
    }

    let mut outputs = vec![intent::Output::Offchain(bitcoin::TxOut {
        script_pubkey: buyer_dest.to_p2tr_script_pubkey(),
        value: release_plan.buyer_amount,
    })];

    for fee_output in &release_plan.effective_fee_outputs {
        outputs.push(intent::Output::Offchain(bitcoin::TxOut {
            script_pubkey: fee_output.address.to_p2tr_script_pubkey(),
            value: fee_output.amount,
        }));
    }

    let forfeit_address = &server_info.forfeit_address;

    batch::prepare_delegate_psbts(
        intent_inputs,
        outputs,
        delegate_cosigner_pk,
        forfeit_address,
        server_info.dust,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("preparing delegate PSBTs")
}

/// Sign the delegate PSBTs (intent + forfeits) with a single keypair.
///
/// This is used by the escrow leaf signers to add their escrow-leaf
/// signature to the delegate PSBTs.
#[deprecated(note = "use refresh::sign_refresh")]
pub fn sign_delegate(delegate: &mut Delegate, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    batch::sign_delegate_psbts(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        &mut delegate.intent.proof,
        &mut delegate.forfeit_psbts,
    )
    .map_err(|e| anyhow::anyhow!("{e:#}"))
    .context("signing delegate PSBTs")
}

/// Execute a delegate settlement via the Arkade batch ceremony.
///
/// This is a standalone implementation of the batch protocol that only needs
/// an `ark_grpc::Client` and server info — no full ark-client wallet or
/// blockchain backend required.
///
/// Blocks until the batch ceremony completes (~10-30s). Returns the
/// commitment transaction ID.
#[deprecated(note = "use refresh::execute_refresh or EscrowClient::refresh_escrow")]
pub async fn settle_delegate<R: Rng + CryptoRng>(
    grpc: &ark_grpc::Client,
    server_info: &server::Info,
    rng: &mut R,
    delegate: Delegate,
    cosigner_kp: Keypair,
) -> Result<Txid> {
    anyhow::ensure!(
        cosigner_kp.public_key() == delegate.delegate_cosigner_pk,
        "cosigner keypair does not match delegate_cosigner_pk",
    );

    // Register the pre-signed intent.
    let intent_id = grpc
        .register_intent(delegate.intent.clone())
        .await
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .context("registering delegated intent")?;

    tracing::debug!(intent_id, "Registered delegated intent");

    let (ark_forfeit_pk, _) = server_info.forfeit_pk.x_only_public_key();

    let own_cosigner_kps = [cosigner_kp];
    let own_cosigner_pks: Vec<_> = own_cosigner_kps.iter().map(|k| k.public_key()).collect();

    let vtxo_input_outpoints: Vec<_> = delegate
        .forfeit_psbts
        .iter()
        .map(|psbt| psbt.unsigned_tx.input[0].previous_output)
        .collect();

    let topics = vtxo_input_outpoints
        .iter()
        .map(ToString::to_string)
        .chain(
            own_cosigner_pks
                .iter()
                .map(|pk| bitcoin::hex::DisplayHex::to_lower_hex_string(&pk.serialize())),
        )
        .collect();

    let mut stream = grpc
        .get_event_stream(topics)
        .await
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .context("getting event stream")?;

    #[derive(Debug, PartialEq, Eq)]
    enum Step {
        Start,
        BatchStarted,
        BatchSigningStarted,
        Finalized,
    }

    let mut step = Step::Start;
    let mut batch_id: Option<String> = None;
    let mut unsigned_commitment_tx = None;
    let mut vtxo_graph_chunks = Some(Vec::new());
    let mut vtxo_graph: Option<TxGraph> = None;
    let mut connectors_graph_chunks = Some(Vec::new());
    let mut batch_expiry = None;
    let mut agg_nonce_pks = HashMap::new();
    let mut our_nonce_trees: Option<HashMap<Keypair, NonceKps>> = None;

    use futures::StreamExt as _;

    loop {
        match stream.next().await {
            Some(Ok(event)) => match event {
                StreamEvent::BatchStarted(e) => {
                    if step != Step::Start {
                        continue;
                    }

                    let hash = sha256::Hash::hash(intent_id.as_bytes());
                    let hash_hex =
                        bitcoin::hex::DisplayHex::to_lower_hex_string(hash.as_byte_array());

                    if e.intent_id_hashes.iter().any(|h| h == &hash_hex) {
                        grpc.confirm_registration(intent_id.clone())
                            .await
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("confirming intent registration")?;

                        tracing::info!(batch_id = e.id, intent_id, "Intent confirmed for batch");

                        batch_id = Some(e.id);
                        batch_expiry = Some(e.batch_expiry);
                        step = Step::BatchStarted;
                    }
                }
                StreamEvent::TreeTx(e) => {
                    if step != Step::BatchStarted && step != Step::BatchSigningStarted {
                        continue;
                    }
                    match e.batch_tree_event_type {
                        BatchTreeEventType::Vtxo => {
                            vtxo_graph_chunks
                                .as_mut()
                                .context("unexpected VTXO graph chunk")?
                                .push(e.tx_graph_chunk);
                        }
                        BatchTreeEventType::Connector => {
                            connectors_graph_chunks
                                .as_mut()
                                .context("unexpected connector graph chunk")?
                                .push(e.tx_graph_chunk);
                        }
                    }
                }
                StreamEvent::TreeSignature(e) => {
                    if step != Step::BatchSigningStarted {
                        continue;
                    }
                    if let BatchTreeEventType::Vtxo = e.batch_tree_event_type {
                        if let Some(ref mut vg) = vtxo_graph {
                            vg.apply(|graph| {
                                if graph.root().unsigned_tx.compute_txid() != e.txid {
                                    Ok(true)
                                } else {
                                    graph.set_signature(e.signature);
                                    Ok(false)
                                }
                            })
                            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                        }
                    }
                }
                StreamEvent::TreeSigningStarted(e) => {
                    if step != Step::BatchStarted {
                        continue;
                    }

                    let chunks = vtxo_graph_chunks
                        .take()
                        .context("signing started without VTXO graph")?;
                    vtxo_graph = Some(
                        TxGraph::new(chunks)
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("building VTXO graph")?,
                    );

                    for own_cosigner_pk in &own_cosigner_pks {
                        if !e.cosigners_pubkeys.iter().any(|p| p == own_cosigner_pk) {
                            anyhow::bail!(
                                "own cosigner PK not in batch cosigners: {own_cosigner_pk}"
                            );
                        }
                    }

                    let mut nonce_map = HashMap::new();
                    for kp in &own_cosigner_kps {
                        let pk = kp.public_key();
                        let nonce_tree = generate_nonce_tree(
                            rng,
                            vtxo_graph.as_ref().unwrap(),
                            pk,
                            &e.unsigned_commitment_tx,
                        )
                        .map_err(|e| anyhow::anyhow!("{e:#}"))
                        .context("generating nonce tree")?;

                        grpc.submit_tree_nonces(&e.id, pk, nonce_tree.to_nonce_pks())
                            .await
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("submitting nonce tree")?;

                        nonce_map.insert(*kp, nonce_tree);
                    }

                    unsigned_commitment_tx = Some(e.unsigned_commitment_tx);
                    our_nonce_trees = Some(nonce_map);
                    step = Step::BatchSigningStarted;
                }
                StreamEvent::TreeNonces(e) => {
                    if step != Step::BatchSigningStarted {
                        continue;
                    }

                    let cosigner_pk = match e.nonces.0.iter().find(|(pk, _)| {
                        own_cosigner_pks
                            .iter()
                            .any(|p| &&p.x_only_public_key().0 == pk)
                    }) {
                        Some((pk, _)) => *pk,
                        None => continue,
                    };

                    let agg_nonce_pk = aggregate_nonces(e.nonces);
                    agg_nonce_pks.insert(e.txid, agg_nonce_pk);

                    let vg = vtxo_graph
                        .as_ref()
                        .context("tree nonces received before signing started")?;

                    if agg_nonce_pks.len() == vg.nb_of_nodes() {
                        let kp = own_cosigner_kps
                            .iter()
                            .find(|kp| kp.public_key().x_only_public_key().0 == cosigner_pk)
                            .context("no cosigner keypair for own PK")?;

                        let nonce_trees =
                            our_nonce_trees.as_mut().context("missing nonce trees")?;
                        let nonce_tree = nonce_trees.get_mut(kp).context("missing nonce tree")?;
                        let commit_tx = unsigned_commitment_tx
                            .as_ref()
                            .context("missing commitment TX")?;
                        let expiry = batch_expiry.context("missing batch expiry")?;

                        let mut partial_sigs = PartialSigTree::default();
                        for (txid, _) in vg.as_map() {
                            let anp = agg_nonce_pks
                                .get(&txid)
                                .context("missing agg nonce for TX")?;

                            let sigs = sign_batch_tree_tx(
                                txid,
                                expiry,
                                ark_forfeit_pk,
                                kp,
                                *anp,
                                vg,
                                commit_tx,
                                nonce_tree,
                            )
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("signing VTXO tree")?;

                            partial_sigs.0.extend(sigs.0);
                        }

                        grpc.submit_tree_signatures(&e.id, kp.public_key(), partial_sigs)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("submitting tree signatures")?;
                    }
                }
                StreamEvent::TreeNoncesAggregated(_) => {}
                StreamEvent::BatchFinalization(_e) => {
                    if step != Step::BatchSigningStarted {
                        continue;
                    }

                    let chunks = connectors_graph_chunks
                        .take()
                        .context("finalization without connectors")?;

                    if !chunks.is_empty() {
                        let connectors = TxGraph::new(chunks)
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("building connectors graph")?;

                        let signed_forfeits = complete_delegate_forfeit_txs(
                            &delegate.forfeit_psbts,
                            &connectors.leaves(),
                        )
                        .map_err(|e| anyhow::anyhow!("{e:#}"))
                        .context("completing forfeit TXs")?;

                        grpc.submit_signed_forfeit_txs(signed_forfeits, None)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .context("submitting forfeit TXs")?;
                    }

                    step = Step::Finalized;
                }
                StreamEvent::BatchFinalized(e) => {
                    if step != Step::Finalized {
                        continue;
                    }
                    tracing::info!(
                        batch_id = e.id,
                        %e.commitment_txid,
                        "Delegated batch finalized"
                    );
                    return Ok(e.commitment_txid);
                }
                StreamEvent::BatchFailed(ref e) => {
                    if Some(&e.id) == batch_id.as_ref() {
                        anyhow::bail!("batch failed {}: {}", e.id, e.reason);
                    }
                }
                StreamEvent::Heartbeat => {}
            },
            Some(Err(e)) => {
                anyhow::bail!("event stream error: {e}");
            }
            None => {
                anyhow::bail!("event stream ended unexpectedly");
            }
        }
    }
}

#[allow(deprecated)]
fn build_intent_inputs(
    vtxos: &[DelegateVtxo],
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
