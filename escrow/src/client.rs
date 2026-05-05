use std::collections::HashMap;

use anyhow::{Context, Result};
use ark_core::VtxoList;
use ark_core::batch::Delegate;
use ark_core::server::{self, GetVtxosRequest};
use bitcoin::key::Keypair;
use bitcoin::{Psbt, Txid};
use rand::rngs::OsRng;

use crate::contract::EscrowContract;
#[allow(deprecated)]
use crate::delegate::DelegateVtxo;
use crate::refresh::{RefreshIntent, RefreshVtxo};
use crate::spend::{self, EscrowVtxo};
use crate::spend_store::{PendingSpend, SpendStore, psbt_from_base64, psbt_to_base64};

/// Wraps an `ark_grpc::Client` with escrow-specific helpers.
pub struct EscrowClient {
    grpc: ark_grpc::Client,
    server_info: Option<server::Info>,
}

impl EscrowClient {
    pub fn new(url: &str) -> Self {
        Self {
            grpc: ark_grpc::Client::new(url.to_string()),
            server_info: None,
        }
    }

    /// Connect to the Arkade server and fetch server info.
    pub async fn connect(&mut self) -> Result<&server::Info> {
        // Ensure a TLS crypto provider is installed (needed for https:// URLs)
        let _ = rustls::crypto::ring::default_provider().install_default();
        self.grpc.connect().await.context("connecting to Arkade")?;
        let info = self.grpc.get_info().await.context("getting server info")?;
        self.server_info = Some(info);
        Ok(self.server_info.as_ref().unwrap())
    }

    pub fn server_info(&self) -> Result<&server::Info> {
        self.server_info
            .as_ref()
            .context("not connected — call connect() first")
    }

    /// Find the escrow VTXO on Arkade by looking up the contract's address.
    ///
    /// Returns the first spendable offchain VTXO matching the escrow address,
    /// or None if no funded escrow exists.
    pub async fn find_escrow_vtxo(&self, contract: &EscrowContract) -> Result<Option<EscrowVtxo>> {
        let info = self.server_info()?;
        let address = contract.address();

        let request = GetVtxosRequest::new_for_addresses(std::iter::once(address));
        let response = self
            .grpc
            .list_vtxos(request)
            .await
            .context("listing VTXOs")?;

        let vtxo_list = VtxoList::new(info.dust, response.vtxos);

        let vtxo = vtxo_list.spendable_offchain().next();

        Ok(vtxo.map(|v| EscrowVtxo {
            outpoint: v.outpoint,
            amount: v.amount,
        }))
    }

    /// Find all unspent escrow VTXOs and report whether any are recoverable.
    ///
    /// Returns `(vtxos, any_recoverable)` where `vtxos` contains all unspent
    /// VTXOs at the escrow address and `any_recoverable` is true if offchain
    /// spending is not possible for at least one of them.
    pub async fn find_refresh_vtxos(
        &self,
        contract: &EscrowContract,
    ) -> Result<(Vec<RefreshVtxo>, bool)> {
        let info = self.server_info()?;
        let address = contract.address();

        let request = GetVtxosRequest::new_for_addresses(std::iter::once(address));
        let response = self
            .grpc
            .list_vtxos(request)
            .await
            .context("listing VTXOs")?;

        let vtxo_list = VtxoList::new(info.dust, response.vtxos);

        let mut vtxos = Vec::new();
        let mut any_recoverable = false;

        for v in vtxo_list.spendable_offchain() {
            vtxos.push(RefreshVtxo {
                outpoint: v.outpoint,
                amount: v.amount,
                is_swept: v.is_swept,
            });
        }

        for v in vtxo_list.recoverable() {
            any_recoverable = true;
            vtxos.push(RefreshVtxo {
                outpoint: v.outpoint,
                amount: v.amount,
                is_swept: v.is_swept,
            });
        }

        Ok((vtxos, any_recoverable))
    }

    /// Find all unspent escrow VTXOs and check recoverability.
    ///
    /// Deprecated: use [`EscrowClient::find_refresh_vtxos`] for refresh flows.
    #[allow(deprecated)]
    pub async fn find_escrow_vtxos(
        &self,
        contract: &EscrowContract,
    ) -> Result<(Vec<DelegateVtxo>, bool)> {
        let (vtxos, any_recoverable) = self.find_refresh_vtxos(contract).await?;
        Ok((
            vtxos
                .into_iter()
                .map(|v| DelegateVtxo {
                    outpoint: v.outpoint,
                    amount: v.amount,
                    is_swept: v.is_swept,
                })
                .collect(),
            any_recoverable,
        ))
    }

    /// Execute a refresh via the Arkade batch ceremony.
    ///
    /// The `refresh` must contain fully-signed intent + forfeit PSBTs (signed
    /// by all selected escrow-leaf parties). The `refresh_cosigner_kp` is the
    /// refresh cosigner keypair whose public key was committed in the intent.
    ///
    /// Blocks until the batch ceremony completes (~10-30s). Returns the
    /// commitment transaction ID.
    pub async fn refresh_escrow(
        &self,
        refresh: RefreshIntent,
        refresh_cosigner_kp: Keypair,
    ) -> Result<Txid> {
        let info = self.server_info()?;
        let mut rng = OsRng;

        crate::refresh::execute_refresh(&self.grpc, info, &mut rng, refresh, refresh_cosigner_kp)
            .await
    }

    /// Execute a delegate settlement via the Arkade batch ceremony.
    ///
    /// Deprecated: use [`EscrowClient::refresh_escrow`] for recoverable escrow
    /// VTXOs, then perform the normal offchain flow.
    #[deprecated(
        note = "direct delegate settlement is legacy; use refresh_escrow followed by normal offchain spend"
    )]
    pub async fn settle_delegate(&self, delegate: Delegate, cosigner_kp: Keypair) -> Result<Txid> {
        let info = self.server_info()?;
        let mut rng = OsRng;

        #[allow(deprecated)]
        crate::delegate::settle_delegate(&self.grpc, info, &mut rng, delegate, cosigner_kp).await
    }

    /// Spend an escrow VTXO offchain with crash recovery via the
    /// [`SpendStore`].
    ///
    /// Wraps the two-phase Arkade protocol (submit + finalize) with a
    /// persistence guard so that a crash between the two steps is recoverable.
    ///
    /// # Flow
    ///
    /// 1. Check the store for a pending spend with `id`. If found, load the
    ///    fully-signed checkpoints from the store and jump straight to
    ///    finalization.
    /// 2. Otherwise: submit the `merged_ark_tx` + `unsigned_checkpoints` to
    ///    Arkade, merge all checkpoint signatures (server + each party),
    ///    persist the fully-signed checkpoints, then finalize and clean up.
    ///
    /// # Arguments
    ///
    /// - `store` — persistence backend for crash recovery. For now, callers
    ///   may also use this as a local proxy for "pending offchain spend"
    ///   status until Arkade exposes that status explicitly for escrow VTXOs.
    /// - `id` — application-level identifier for deduplication (e.g. trade ID).
    /// - `merged_ark_tx` — the ark_tx PSBT with all non-server signatures
    ///   already merged (e.g. arbiter + buyer, or arbiter + seller).
    /// - `unsigned_checkpoints` — the raw unsigned checkpoint PSBTs (sent to
    ///   Arkade during submit so the server never sees party checkpoint sigs
    ///   before co-signing the ark_tx).
    /// - `party_signed_checkpoints` — each signing party's independently signed
    ///   checkpoint PSBTs. Outer slice: one entry per party. Inner slice: one
    ///   PSBT per checkpoint, matching `unsigned_checkpoints` in order.
    ///
    /// # Returns
    ///
    /// The Arkade transaction ID on success.
    pub async fn spend_escrow_offchain(
        &self,
        store: &(impl SpendStore + ?Sized),
        id: &str,
        merged_ark_tx: Psbt,
        unsigned_checkpoints: Vec<Psbt>,
        party_signed_checkpoints: &[&[Psbt]],
    ) -> Result<Txid> {
        // Step 1: Check for a pending spend from a previous attempt.
        if let Some(pending) = store.load(id).context("loading pending spend")? {
            let ark_txid: Txid = pending
                .ark_txid
                .parse()
                .context("invalid ark_txid in pending spend")?;

            tracing::info!(%ark_txid, "Resuming finalization of pending spend");

            let final_checkpoints: Vec<Psbt> = pending
                .signed_checkpoints
                .iter()
                .map(|b64| psbt_from_base64(b64))
                .collect::<Result<_>>()
                .context("decoding persisted checkpoint PSBTs")?;

            self.finalize_internal(ark_txid, final_checkpoints).await?;

            store.remove(id).context("removing finalized spend")?;
            return Ok(ark_txid);
        }

        // Validate checkpoint counts before submitting (can't recover if
        // submit succeeds but merge fails due to mismatched lengths).
        let expected = unsigned_checkpoints.len();
        for (i, party_cps) in party_signed_checkpoints.iter().enumerate() {
            anyhow::ensure!(
                party_cps.len() == expected,
                "party {i} has {} checkpoints, expected {expected}",
                party_cps.len(),
            );
        }

        // Step 2: Fresh submit.
        let (ark_txid, server_checkpoints) = self
            .submit_internal(merged_ark_tx, unsigned_checkpoints)
            .await
            .context("submitting offchain transaction")?;

        // Step 3: Merge all checkpoint sigs (server + each party).
        let final_checkpoints =
            Self::merge_all_checkpoint_sigs(&server_checkpoints, party_signed_checkpoints)?;

        // Persist the fully-signed checkpoints before finalizing so a crash
        // between submit and finalize is recoverable on the next call.
        let pending = PendingSpend {
            id: id.to_string(),
            ark_txid: ark_txid.to_string(),
            signed_checkpoints: final_checkpoints.iter().map(psbt_to_base64).collect(),
        };
        store.save(&pending).context("persisting pending spend")?;

        tracing::info!(%ark_txid, "Submitted offchain TX, attempting finalization");

        // Step 4: Finalize and clean up.
        self.finalize_internal(ark_txid, final_checkpoints).await?;

        store.remove(id).context("removing finalized spend")?;
        Ok(ark_txid)
    }

    /// Access the underlying gRPC client.
    pub fn grpc(&self) -> &ark_grpc::Client {
        &self.grpc
    }

    // --- Internal helpers ---

    /// Submit a signed ark_tx + unsigned checkpoint PSBTs to the Arkade server.
    ///
    /// Returns the ark txid and server-signed checkpoint PSBTs (with
    /// witness_scripts restored).
    async fn submit_internal(
        &self,
        ark_tx: Psbt,
        checkpoint_txs: Vec<Psbt>,
    ) -> Result<(Txid, Vec<Psbt>)> {
        let ark_txid = ark_tx.unsigned_tx.compute_txid();

        let res = self
            .grpc
            .submit_offchain_transaction_request(ark_tx, checkpoint_txs.clone())
            .await
            .context("submitting offchain transaction")?;

        // Build a map from original checkpoint txid → witness_script so we can
        // restore witness_script on the server-returned checkpoints (the server
        // may strip it).
        let witness_scripts: HashMap<Txid, _> = checkpoint_txs
            .iter()
            .map(|cp| {
                let txid = cp.unsigned_tx.compute_txid();
                let ws = cp.inputs[0].witness_script.clone();
                (txid, ws)
            })
            .collect();

        let signed_checkpoints = res
            .signed_checkpoint_txs
            .into_iter()
            .map(|mut cp| {
                let txid = cp.unsigned_tx.compute_txid();
                if let Some(ws) = witness_scripts.get(&txid) {
                    cp.inputs[0].witness_script = ws.clone();
                }
                cp
            })
            .collect();

        Ok((ark_txid, signed_checkpoints))
    }

    /// Finalize the offchain transaction with fully-signed checkpoint PSBTs.
    async fn finalize_internal(
        &self,
        ark_txid: Txid,
        signed_checkpoint_txs: Vec<Psbt>,
    ) -> Result<()> {
        self.grpc
            .finalize_offchain_transaction(ark_txid, signed_checkpoint_txs)
            .await
            .context("finalizing offchain transaction")?;
        Ok(())
    }

    /// Merge server-signed checkpoints with each party's signed checkpoints.
    ///
    /// For each checkpoint position, starts from the server-signed PSBT and
    /// merges in every party's `tap_script_sigs`.
    fn merge_all_checkpoint_sigs(
        server_checkpoints: &[Psbt],
        party_signed_checkpoints: &[&[Psbt]],
    ) -> Result<Vec<Psbt>> {
        server_checkpoints
            .iter()
            .enumerate()
            .map(|(i, server_cp)| {
                let mut merged = server_cp.clone();
                for party_cps in party_signed_checkpoints {
                    anyhow::ensure!(
                        party_cps.len() == server_checkpoints.len(),
                        "party has {} checkpoints, expected {}",
                        party_cps.len(),
                        server_checkpoints.len(),
                    );
                    spend::merge_ark_tx_sigs(&mut merged, &party_cps[i])?;
                }
                Ok(merged)
            })
            .collect()
    }
}
