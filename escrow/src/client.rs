use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use ark_core::VtxoList;
use ark_core::batch::Delegate;
use ark_core::server::{self, GetVtxosRequest};
use bitcoin::key::Keypair;
use bitcoin::{OutPoint, Psbt, ScriptBuf, Txid, XOnlyPublicKey};
use rand::rngs::OsRng;

use crate::FeeOutput;
use crate::contract::{EscrowContract, SignerSet};
#[allow(deprecated)]
use crate::delegate::DelegateVtxo;
use crate::refresh::{RefreshInput, RefreshIntent, RefreshVtxo};
use crate::spend::{self, EscrowVtxo};
use crate::spend_store::{PendingSpend, SpendStage, SpendStore, psbt_from_base64, psbt_to_base64};

#[derive(Clone, Debug)]
pub struct EscrowVtxoStatus {
    pub outpoint: OutPoint,
    pub created_at: i64,
    pub expires_at: i64,
    pub amount: bitcoin::Amount,
    pub spendable_offchain: bool,
    pub recoverable: bool,
    pub is_swept: bool,
}

struct ResolvedEscrowVtxo {
    contract: EscrowContract,
    vtxo: EscrowVtxo,
}

struct ResolvedRefreshVtxo {
    contract: EscrowContract,
    vtxo: RefreshVtxo,
}

/// Wraps an `ark_grpc::Client` with escrow-specific helpers.
#[derive(Clone)]
pub struct EscrowClient {
    grpc: ark_grpc::Client,
    server_info: Arc<RwLock<Option<server::Info>>>,
    timeout: Option<Duration>,
    refresh_timeout: Option<Duration>,
}

impl EscrowClient {
    pub fn new(url: &str) -> Self {
        let server_info = Arc::new(RwLock::new(None));
        let mut grpc = ark_grpc::Client::new(url.to_string());

        let hook_server_info = server_info.clone();
        grpc.set_info_refresh_hook(move |info| {
            let mut guard = hook_server_info.write().map_err(
                |_| -> Box<dyn std::error::Error + Send + Sync> {
                    "server info cache lock poisoned".into()
                },
            )?;
            *guard = Some(info);
            Ok(())
        });

        Self {
            grpc,
            server_info,
            timeout: None,
            refresh_timeout: Some(Duration::from_secs(120)),
        }
    }

    pub fn new_with_timeout(url: &str, timeout: Duration) -> Self {
        let mut client = Self::new(url);
        client.set_timeout(Some(timeout));
        client
    }

    /// Set the timeout applied to Arkade network operations other than refresh.
    /// `None` disables this timeout. Refresh has its own ceremony deadline; see
    /// [`Self::set_refresh_timeout`].
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Set the overall deadline for a refresh batch ceremony (default: 120s).
    /// This includes intent registration and waiting for batch events. Configure
    /// it to accommodate the server's batch schedule and signing time.
    /// `None` disables the refresh deadline. The ordinary request timeout is
    /// independent and does not apply inside the ceremony.
    pub fn set_refresh_timeout(&mut self, timeout: Option<Duration>) {
        self.refresh_timeout = timeout;
    }

    pub fn refresh_timeout(&self) -> Option<Duration> {
        self.refresh_timeout
    }

    /// Connect to the Arkade server and fetch server info.
    pub async fn connect(&mut self) -> Result<server::Info> {
        // Ensure a TLS crypto provider is installed (needed for https:// URLs)
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self::run_with_timeout(self.timeout, "connecting to Arkade", self.grpc.connect())
            .await
            .context("connecting to Arkade")?;
        let info =
            Self::run_with_timeout(self.timeout, "getting server info", self.grpc.get_info())
                .await
                .context("getting server info")?;
        self.store_server_info(info.clone())?;
        Ok(info)
    }

    pub fn server_info(&self) -> Result<server::Info> {
        self.server_info
            .read()
            .map_err(|_| anyhow::anyhow!("server info cache lock poisoned"))?
            .clone()
            .context("not connected — call connect() first")
    }

    /// Find the escrow VTXO on Arkade by looking up the contract's address.
    ///
    /// Returns the first spendable offchain VTXO matching the escrow address,
    /// or None if no funded escrow exists. If the escrow address was funded
    /// more than once, use [`EscrowClient::find_spendable_escrow_vtxos`] or
    /// [`EscrowClient::build_release_for_outpoint`] to choose a specific VTXO.
    pub async fn find_escrow_vtxo(&self, contract: &EscrowContract) -> Result<Option<EscrowVtxo>> {
        Ok(self
            .find_spendable_escrow_vtxos(contract)
            .await?
            .into_iter()
            .next())
    }

    /// Find all escrow VTXOs that can currently be spent offchain.
    pub async fn find_spendable_escrow_vtxos(
        &self,
        contract: &EscrowContract,
    ) -> Result<Vec<EscrowVtxo>> {
        let (_, _, vtxo_list) = self.list_candidate_vtxos(contract).await?;

        Ok(vtxo_list
            .spendable_offchain()
            .map(|v| EscrowVtxo {
                outpoint: v.outpoint,
                amount: v.amount,
            })
            .collect())
    }

    /// Find all unspent escrow VTXOs with enough status metadata for caller-side selection.
    pub async fn find_escrow_vtxo_statuses(
        &self,
        contract: &EscrowContract,
    ) -> Result<Vec<EscrowVtxoStatus>> {
        let (_, _, vtxo_list) = self.list_candidate_vtxos(contract).await?;

        Ok(vtxo_list
            .spendable_offchain()
            .map(|v| EscrowVtxoStatus {
                outpoint: v.outpoint,
                created_at: v.created_at,
                expires_at: v.expires_at,
                amount: v.amount,
                spendable_offchain: true,
                recoverable: false,
                is_swept: v.is_swept,
            })
            .chain(vtxo_list.recoverable().map(|v| EscrowVtxoStatus {
                outpoint: v.outpoint,
                created_at: v.created_at,
                expires_at: v.expires_at,
                amount: v.amount,
                spendable_offchain: false,
                recoverable: true,
                is_swept: v.is_swept,
            }))
            .collect())
    }

    /// Find one spendable escrow VTXO by outpoint.
    pub async fn find_spendable_escrow_vtxo_by_outpoint(
        &self,
        contract: &EscrowContract,
        outpoint: OutPoint,
    ) -> Result<Option<EscrowVtxo>> {
        Ok(self
            .find_spendable_escrow_vtxos(contract)
            .await?
            .into_iter()
            .find(|v| v.outpoint == outpoint))
    }

    /// Build a release transaction for a specific spendable escrow VTXO.
    ///
    /// The VTXO amount is loaded from Arkade, avoiding caller-supplied amount
    /// mismatches when the escrow address has multiple VTXOs.
    pub async fn build_release_for_outpoint(
        &self,
        contract: &EscrowContract,
        outpoint: OutPoint,
        buyer_dest: &ark_core::ArkAddress,
        fee_outputs: &[FeeOutput],
        signer_set: SignerSet,
    ) -> Result<spend::EscrowTransaction> {
        let (info, resolved) = self
            .resolve_spendable_escrow_vtxo(contract, outpoint)
            .await?;

        spend::build_release_tx(
            &resolved.contract,
            &resolved.vtxo,
            buyer_dest,
            fee_outputs,
            signer_set,
            &info,
        )
    }

    /// Build a refund transaction for a specific spendable escrow VTXO.
    ///
    /// The VTXO amount is loaded from Arkade, avoiding caller-supplied amount
    /// mismatches when the escrow address has multiple VTXOs.
    pub async fn build_refund_for_outpoint(
        &self,
        contract: &EscrowContract,
        outpoint: OutPoint,
        seller_dest: &ark_core::ArkAddress,
        signer_set: SignerSet,
    ) -> Result<spend::EscrowTransaction> {
        let (info, resolved) = self
            .resolve_spendable_escrow_vtxo(contract, outpoint)
            .await?;

        spend::build_refund_tx(
            &resolved.contract,
            &resolved.vtxo,
            seller_dest,
            signer_set,
            &info,
        )
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
        let (_, _, vtxo_list) = self.list_candidate_vtxos(contract).await?;

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

    /// Prepare a refresh intent, resolving old/current server signer contracts automatically.
    pub async fn prepare_refresh(
        &self,
        contract: &EscrowContract,
        vtxos: &[RefreshVtxo],
        signer_set: SignerSet,
        refresh_cosigner_pk: bitcoin::secp256k1::PublicKey,
    ) -> Result<RefreshIntent> {
        let (info, resolved_vtxos) = self.resolve_refresh_vtxos(contract, vtxos).await?;
        let inputs = resolved_vtxos
            .iter()
            .map(|resolved| RefreshInput {
                contract: &resolved.contract,
                vtxo: &resolved.vtxo,
            })
            .collect::<Vec<_>>();

        crate::refresh::prepare_refresh_resolved(
            contract,
            &inputs,
            signer_set,
            refresh_cosigner_pk,
            &info,
        )
    }

    /// Execute a refresh via the Arkade batch ceremony.
    ///
    /// The `refresh` must contain fully-signed intent + forfeit PSBTs (signed
    /// by all selected escrow-leaf parties). The `refresh_cosigner_kp` is the
    /// refresh cosigner keypair whose public key was committed in the intent.
    ///
    /// Blocks until the batch ceremony completes (~10-30s). Returns the
    /// commitment transaction ID. Uses [`Self::refresh_timeout`] for the entire
    /// ceremony, independently of [`Self::timeout`].
    pub async fn refresh_escrow(
        &self,
        refresh: RefreshIntent,
        refresh_cosigner_kp: Keypair,
    ) -> Result<Txid> {
        let info = self.server_info()?;
        let mut rng = OsRng;

        Self::run_with_timeout(
            self.refresh_timeout,
            "refreshing escrow",
            crate::refresh::execute_refresh(
                &self.grpc,
                &info,
                &mut rng,
                refresh,
                refresh_cosigner_kp,
            ),
        )
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
        Self::run_with_timeout(
            self.timeout,
            "settling delegate",
            crate::delegate::settle_delegate(&self.grpc, &info, &mut rng, delegate, cosigner_kp),
        )
        .await
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
    /// - `store` — persistence backend for crash recovery. A record is written
    ///   *before* `submit` is sent and removed only after `finalize` succeeds
    ///   or the server definitively rejects the submit. Calling this method
    ///   again with the same `id` (or [`resume_pending_spend`]) resumes from
    ///   the recorded stage. Callers may also use the store as a local proxy
    ///   for "pending offchain spend" status until Arkade exposes that status
    ///   explicitly for escrow VTXOs.
    /// - `id` — application-level identifier for deduplication (e.g. trade ID).
    ///   While a record exists for `id`, the persisted transaction is resumed
    ///   and the other arguments are ignored.
    ///
    /// # Recovery limits
    ///
    /// A record at the `submitting` stage is re-submitted as recorded. If the
    /// server had already accepted the original request (response lost in
    /// flight), the re-submit fails because the inputs are locked, and the
    /// record is kept for operator follow-up: the server's checkpoint
    /// signatures only exist in the lost response. Recovering them needs
    /// `GetPendingTx` with a proof signed by both escrow parties, which this
    /// crate does not implement yet.
    ///
    /// [`resume_pending_spend`]: EscrowClient::resume_pending_spend
    /// - `merged_ark_tx` — the ark_tx PSBT with all non-server signatures
    ///   already merged (e.g. arbiter + buyer, or arbiter + seller).
    /// - `unsigned_checkpoints` — the raw unsigned checkpoint PSBTs (sent to
    ///   Arkade during submit so the server never sees party checkpoint sigs
    ///   before co-signing the ark_tx).
    /// - `party_signed_checkpoints` — each signing party's independently signed
    ///   checkpoint PSBTs. Outer slice: one entry per party. Inner slice: one
    ///   PSBT per checkpoint, matching `unsigned_checkpoints` in order.
    ///
    /// # Concurrency
    ///
    /// Callers must not run two calls for the same `id` concurrently; the
    /// store is not a lock. If they do, the attempt token in the record keeps
    /// a finished attempt from deleting a record written by the other one.
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
        // Resume a previous attempt if one is recorded.
        if let Some(pending) = store.load(id).context("loading pending spend")? {
            return self.resume_recorded(store, pending).await;
        }

        // Validate everything that could make the post-submit merge fail
        // before persisting or sending anything: once the server has
        // accepted the submit, a merge failure would strand its signatures.
        let expected = unsigned_checkpoints.len();
        anyhow::ensure!(expected > 0, "no checkpoints to submit");
        for (i, party_cps) in party_signed_checkpoints.iter().enumerate() {
            anyhow::ensure!(
                party_cps.len() == expected,
                "party {i} has {} checkpoints, expected {expected}",
                party_cps.len(),
            );
            for (j, (party_cp, unsigned_cp)) in
                party_cps.iter().zip(&unsigned_checkpoints).enumerate()
            {
                anyhow::ensure!(
                    party_cp.unsigned_tx == unsigned_cp.unsigned_tx
                        && party_cp.inputs.len() == unsigned_cp.inputs.len(),
                    "party {i} checkpoint {j} does not match unsigned checkpoint {j}",
                );
            }
        }

        let ark_txid = merged_ark_tx.unsigned_tx.compute_txid();
        let pending = PendingSpend {
            id: id.to_string(),
            ark_txid: ark_txid.to_string(),
            signed_checkpoints: vec![],
            stage: SpendStage::Submitting,
            token: PendingSpend::new_token(),
            ark_tx: Some(psbt_to_base64(&merged_ark_tx)),
            unsigned_checkpoints: unsigned_checkpoints.iter().map(psbt_to_base64).collect(),
            party_signed_checkpoints: party_signed_checkpoints
                .iter()
                .map(|cps| cps.iter().map(psbt_to_base64).collect())
                .collect(),
        };

        // Persist before the request leaves the process. If this fails,
        // nothing has been sent and the caller can simply retry.
        store
            .save(&pending)
            .context("persisting pending spend before submit")?;

        self.submit_and_finalize(
            store,
            pending,
            merged_ark_tx,
            unsigned_checkpoints,
            party_signed_checkpoints,
            true,
        )
        .await
    }

    /// Resume the recorded spend for `id` without supplying transaction data.
    ///
    /// Returns `Ok(None)` if no record exists. Otherwise behaves exactly like
    /// [`spend_escrow_offchain`] does when it finds a record: re-sends the
    /// recorded `submit` or `finalize`, clears the record on success.
    ///
    /// [`spend_escrow_offchain`]: EscrowClient::spend_escrow_offchain
    pub async fn resume_pending_spend(
        &self,
        store: &(impl SpendStore + ?Sized),
        id: &str,
    ) -> Result<Option<Txid>> {
        match store.load(id).context("loading pending spend")? {
            Some(pending) => self.resume_recorded(store, pending).await.map(Some),
            None => Ok(None),
        }
    }

    /// Drive a recorded spend from its persisted stage to completion.
    async fn resume_recorded(
        &self,
        store: &(impl SpendStore + ?Sized),
        pending: PendingSpend,
    ) -> Result<Txid> {
        let ark_txid: Txid = pending
            .ark_txid
            .parse()
            .context("invalid ark_txid in pending spend")?;

        match pending.stage {
            SpendStage::Submitted => {
                tracing::info!(%ark_txid, "Resuming finalization of pending spend");

                let final_checkpoints: Vec<Psbt> = pending
                    .signed_checkpoints
                    .iter()
                    .map(|b64| psbt_from_base64(b64))
                    .collect::<Result<_>>()
                    .context("decoding persisted checkpoint PSBTs")?;

                self.finalize_and_clear(store, &pending, ark_txid, final_checkpoints)
                    .await
            }
            SpendStage::Submitting => {
                tracing::info!(
                    %ark_txid,
                    "Resuming pending spend whose submit outcome is unknown; resubmitting"
                );

                let ark_tx = pending
                    .ark_tx
                    .as_deref()
                    .context("pending spend at submitting stage has no ark tx")
                    .and_then(psbt_from_base64)
                    .context("decoding persisted ark tx")?;
                let unsigned_checkpoints: Vec<Psbt> = pending
                    .unsigned_checkpoints
                    .iter()
                    .map(|b64| psbt_from_base64(b64))
                    .collect::<Result<_>>()
                    .context("decoding persisted unsigned checkpoints")?;
                let party_cps: Vec<Vec<Psbt>> = pending
                    .party_signed_checkpoints
                    .iter()
                    .map(|cps| cps.iter().map(|b64| psbt_from_base64(b64)).collect())
                    .collect::<Result<_>>()
                    .context("decoding persisted party checkpoints")?;
                let party_refs: Vec<&[Psbt]> = party_cps.iter().map(Vec::as_slice).collect();

                self.submit_and_finalize(
                    store,
                    pending,
                    ark_tx,
                    unsigned_checkpoints,
                    &party_refs,
                    false,
                )
                .await
            }
        }
    }

    /// Submit, record the server's signatures, finalize, clear the record.
    /// `pending` must already be persisted at [`SpendStage::Submitting`].
    ///
    /// `first_attempt` is true when this process wrote the record just now,
    /// so a definitive server rejection proves the server never accepted
    /// the transaction and the record can be cleared. On a resume the same
    /// rejection ("inputs already locked") may be caused by the original,
    /// accepted submit, so the record is kept.
    async fn submit_and_finalize(
        &self,
        store: &(impl SpendStore + ?Sized),
        mut pending: PendingSpend,
        merged_ark_tx: Psbt,
        unsigned_checkpoints: Vec<Psbt>,
        party_signed_checkpoints: &[&[Psbt]],
        first_attempt: bool,
    ) -> Result<Txid> {
        let (ark_txid, server_checkpoints) = match self
            .submit_internal(merged_ark_tx, unsigned_checkpoints)
            .await
        {
            Ok(res) => res,
            Err(e) if first_attempt && Self::is_definitive_rejection(&e) => {
                // The server answered and said no: nothing is locked on its
                // side, so a retry with corrected data must not replay this.
                let cleared = store
                    .remove_if(&pending.id, &pending.token)
                    .context("clearing rejected spend record")?;
                return Err(e.context(format!(
                    "offchain transaction {} rejected by server (pending record {} {})",
                    pending.ark_txid,
                    pending.id,
                    if cleared {
                        "cleared"
                    } else {
                        "not ours; left untouched"
                    }
                )));
            }
            Err(e) => {
                return Err(e.context(format!(
                    "submitting offchain transaction {} (pending record {} retained; \
                     retry with the same id resubmits it)",
                    pending.ark_txid, pending.id
                )));
            }
        };
        anyhow::ensure!(
            ark_txid.to_string() == pending.ark_txid,
            "submitted ark txid {ark_txid} differs from recorded {}",
            pending.ark_txid
        );

        let final_checkpoints =
            Self::merge_all_checkpoint_sigs(&server_checkpoints, party_signed_checkpoints)?;

        // Upgrade the record: from here on a retry only needs to finalize.
        pending.stage = SpendStage::Submitted;
        pending.signed_checkpoints = final_checkpoints.iter().map(psbt_to_base64).collect();
        pending.ark_tx = None;
        pending.unsigned_checkpoints.clear();
        pending.party_signed_checkpoints.clear();
        let saved = match store.save(&pending) {
            Ok(()) => true,
            Err(e) => {
                // The server has accepted the spend. The fully-signed
                // checkpoints are in memory, so finalizing now is still the
                // best outcome; the stale `Submitting` record only matters if
                // finalize fails too, and then the save is retried below.
                tracing::warn!(
                    %ark_txid,
                    error = %e,
                    "Could not persist submitted stage; finalizing from memory"
                );
                false
            }
        };

        tracing::info!(%ark_txid, "Submitted offchain TX, attempting finalization");

        let result = self
            .finalize_and_clear(store, &pending, ark_txid, final_checkpoints)
            .await;
        if result.is_err() && !saved {
            // Last chance to keep the server's signatures: without this the
            // record stays at `submitting` and a retry resubmits locked inputs.
            if let Err(e) = store.save(&pending) {
                tracing::error!(
                    %ark_txid,
                    error = %e,
                    "Could not persist submitted stage after failed finalize; \
                     server signatures are lost, record stays at submitting"
                );
            }
        }
        result
    }

    /// Whether `err` is a gRPC status that proves the server rejected the
    /// request without acting on it.
    ///
    /// Allowlist, not denylist: tonic also produces statuses on the client
    /// side after a response was received (e.g. `OutOfRange` for an oversized
    /// response, `Unimplemented` for unsupported compression), and those must
    /// stay ambiguous. arkd reports every request rejection as
    /// `InvalidArgument`; `FailedPrecondition` is its version/digest gate;
    /// the auth codes are only ever produced before the request is handled.
    fn is_definitive_rejection(err: &anyhow::Error) -> bool {
        err.chain()
            .find_map(|cause| cause.downcast_ref::<tonic::Status>())
            .is_some_and(|status| {
                matches!(
                    status.code(),
                    tonic::Code::InvalidArgument
                        | tonic::Code::FailedPrecondition
                        | tonic::Code::PermissionDenied
                        | tonic::Code::Unauthenticated
                )
                // arkd answers a re-submit of a transaction it already holds
                // with `INVALID_ARK_PSBT: duplicated offchain tx <txid>`.
                // That is the lost-response case, not a rejection: the
                // record must stay so the operator can finalize it.
                && !status.message().contains("duplicated offchain tx")
            })
    }

    #[cfg(test)]
    pub(crate) fn is_definitive_rejection_for_test(err: &anyhow::Error) -> bool {
        Self::is_definitive_rejection(err)
    }

    async fn finalize_and_clear(
        &self,
        store: &(impl SpendStore + ?Sized),
        pending: &PendingSpend,
        ark_txid: Txid,
        final_checkpoints: Vec<Psbt>,
    ) -> Result<Txid> {
        self.finalize_internal(ark_txid, final_checkpoints).await?;

        let removed = store
            .remove_if(&pending.id, &pending.token)
            .context("removing finalized spend")?;
        if !removed {
            tracing::warn!(
                %ark_txid,
                id = %pending.id,
                "Finalized spend record was already replaced or removed; leaving store untouched"
            );
        }
        Ok(ark_txid)
    }

    /// Access the underlying gRPC client.
    pub fn grpc(&self) -> &ark_grpc::Client {
        &self.grpc
    }

    // --- Internal helpers ---

    fn store_server_info(&self, info: server::Info) -> Result<()> {
        *self
            .server_info
            .write()
            .map_err(|_| anyhow::anyhow!("server info cache lock poisoned"))? = Some(info);
        Ok(())
    }

    /// Build one candidate contract per known server key.
    ///
    /// A server key that collides with one of the escrow parties cannot form a
    /// valid contract, so it is skipped rather than failing the whole lookup.
    /// The contract's own server key is always first and always valid, so the
    /// result is never empty.
    fn candidate_contracts(
        contract: &EscrowContract,
        signer_pk: XOnlyPublicKey,
        deprecated_signers: &[server::DeprecatedSigner],
    ) -> Vec<EscrowContract> {
        let mut server_keys = Vec::<XOnlyPublicKey>::new();
        let mut push_unique = |server: XOnlyPublicKey| {
            if !server_keys.contains(&server) {
                server_keys.push(server);
            }
        };

        push_unique(contract.options().server);
        push_unique(signer_pk);
        for deprecated in deprecated_signers {
            push_unique(deprecated.pk.into());
        }

        server_keys
            .into_iter()
            .filter_map(|server| match contract.with_server(server) {
                Ok(candidate) => Some(candidate),
                Err(e) => {
                    tracing::warn!(%server, "Skipping server key that cannot form an escrow contract: {e:#}");
                    None
                }
            })
            .collect()
    }

    async fn list_candidate_vtxos(
        &self,
        contract: &EscrowContract,
    ) -> Result<(server::Info, Vec<EscrowContract>, VtxoList)> {
        let info = self.server_info()?;
        let candidates =
            Self::candidate_contracts(contract, info.signer_pk.into(), &info.deprecated_signers);
        let request =
            GetVtxosRequest::new_for_addresses(candidates.iter().map(EscrowContract::address));

        let response =
            Self::run_with_timeout(self.timeout, "listing VTXOs", self.grpc.list_vtxos(request))
                .await
                .context("listing VTXOs")?;

        let vtxo_list = VtxoList::new(info.dust, response.vtxos);
        Ok((info, candidates, vtxo_list))
    }

    fn contract_for_script(
        candidates: &[EscrowContract],
        script: &ScriptBuf,
    ) -> Result<EscrowContract> {
        candidates
            .iter()
            .find(|contract| contract.script_pubkey() == *script)
            .cloned()
            .with_context(|| format!("escrow contract not found for script pubkey {script}"))
    }

    async fn resolve_spendable_escrow_vtxo(
        &self,
        contract: &EscrowContract,
        outpoint: OutPoint,
    ) -> Result<(server::Info, ResolvedEscrowVtxo)> {
        let (info, candidates, vtxo_list) = self.list_candidate_vtxos(contract).await?;
        let vtxo = vtxo_list
            .spendable_offchain()
            .find(|v| v.outpoint == outpoint)
            .with_context(|| format!("spendable escrow VTXO not found: {outpoint}"))?;
        let contract = Self::contract_for_script(&candidates, &vtxo.script)?;

        Ok((
            info,
            ResolvedEscrowVtxo {
                contract,
                vtxo: EscrowVtxo {
                    outpoint: vtxo.outpoint,
                    amount: vtxo.amount,
                },
            },
        ))
    }

    async fn resolve_refresh_vtxos(
        &self,
        contract: &EscrowContract,
        vtxos: &[RefreshVtxo],
    ) -> Result<(server::Info, Vec<ResolvedRefreshVtxo>)> {
        let (info, candidates, vtxo_list) = self.list_candidate_vtxos(contract).await?;
        let all_unspent = vtxo_list.all_unspent().collect::<Vec<_>>();

        let resolved = vtxos
            .iter()
            .map(|requested| {
                let vtxo = all_unspent
                    .iter()
                    .copied()
                    .find(|v| v.outpoint == requested.outpoint)
                    .with_context(|| {
                        format!(
                            "escrow VTXO not found across signer candidates: {}",
                            requested.outpoint
                        )
                    })?;
                let contract = Self::contract_for_script(&candidates, &vtxo.script)?;

                Ok(ResolvedRefreshVtxo {
                    contract,
                    vtxo: RefreshVtxo {
                        outpoint: vtxo.outpoint,
                        amount: vtxo.amount,
                        is_swept: vtxo.is_swept,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok((info, resolved))
    }

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

        let res = Self::run_with_timeout(
            self.timeout,
            "submitting offchain transaction",
            self.grpc
                .submit_offchain_transaction_request(ark_tx, checkpoint_txs.clone()),
        )
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
        Self::run_with_timeout(
            self.timeout,
            "finalizing offchain transaction",
            self.grpc
                .finalize_offchain_transaction(ark_txid, signed_checkpoint_txs),
        )
        .await
        .context("finalizing offchain transaction")?;
        Ok(())
    }

    async fn run_with_timeout<T, E, F>(
        timeout: Option<Duration>,
        operation: &'static str,
        future: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T, E>>,
        E: Into<anyhow::Error>,
    {
        match timeout {
            Some(duration) => tokio::time::timeout(duration, future)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("{operation} timed out after {}ms", duration.as_millis())
                })?
                .map_err(Into::into),
            None => future.await.map_err(Into::into),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::EscrowOptions;
    use bitcoin::Network;
    use bitcoin::secp256k1::{Secp256k1, rand};

    fn deprecated_signer(pk: bitcoin::secp256k1::PublicKey) -> server::DeprecatedSigner {
        server::DeprecatedSigner { pk, cutoff_date: 0 }
    }

    #[test]
    fn only_server_side_rejection_codes_are_definitive() {
        let wrapped =
            |code| anyhow::Error::new(tonic::Status::new(code, "x")).context("submitting");
        for code in [
            tonic::Code::InvalidArgument,
            tonic::Code::FailedPrecondition,
            tonic::Code::PermissionDenied,
            tonic::Code::Unauthenticated,
        ] {
            assert!(
                EscrowClient::is_definitive_rejection_for_test(&wrapped(code)),
                "{code:?}"
            );
        }
        for code in [
            tonic::Code::OutOfRange,
            tonic::Code::Unimplemented,
            tonic::Code::NotFound,
            tonic::Code::AlreadyExists,
            tonic::Code::Unavailable,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Internal,
            tonic::Code::Unknown,
            tonic::Code::Ok,
        ] {
            assert!(
                !EscrowClient::is_definitive_rejection_for_test(&wrapped(code)),
                "{code:?}"
            );
        }
        // arkd's duplicate-submit answer means the server already holds the
        // transaction: ambiguous for the record's sake, not a rejection.
        assert!(!EscrowClient::is_definitive_rejection_for_test(
            &anyhow::Error::new(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "INVALID_ARK_PSBT (1): duplicated offchain tx 03617dbe"
            ))
            .context("submitting")
        ));
        // No status at all (our own timeout) is ambiguous.
        assert!(!EscrowClient::is_definitive_rejection_for_test(
            &anyhow::anyhow!("submitting offchain transaction timed out after 50ms")
        ));
    }

    #[test]
    fn candidates_skip_a_deprecated_signer_colliding_with_an_escrow_party() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let seller = Keypair::new(&secp, &mut rng);
        let buyer = Keypair::new(&secp, &mut rng);
        let arbiter = Keypair::new(&secp, &mut rng);
        let signer = Keypair::new(&secp, &mut rng);

        let contract = EscrowContract::new(
            EscrowOptions {
                seller: seller.x_only_public_key().0,
                buyer: buyer.x_only_public_key().0,
                arbiter: arbiter.x_only_public_key().0,
                server: signer.x_only_public_key().0,
                unilateral_exit_delay: bitcoin::Sequence(512),
            },
            Network::Regtest,
        )
        .unwrap();

        // The buyer picked a key the server advertises as a deprecated signer.
        let candidates = EscrowClient::candidate_contracts(
            &contract,
            signer.x_only_public_key().0,
            &[deprecated_signer(buyer.public_key())],
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].script_pubkey(), contract.script_pubkey());
    }

    #[test]
    fn candidates_cover_every_collision_free_server_key() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let seller = Keypair::new(&secp, &mut rng);
        let buyer = Keypair::new(&secp, &mut rng);
        let arbiter = Keypair::new(&secp, &mut rng);
        let signer = Keypair::new(&secp, &mut rng);
        let old_signer = Keypair::new(&secp, &mut rng);

        let contract = EscrowContract::new(
            EscrowOptions {
                seller: seller.x_only_public_key().0,
                buyer: buyer.x_only_public_key().0,
                arbiter: arbiter.x_only_public_key().0,
                server: signer.x_only_public_key().0,
                unilateral_exit_delay: bitcoin::Sequence(512),
            },
            Network::Regtest,
        )
        .unwrap();

        let candidates = EscrowClient::candidate_contracts(
            &contract,
            signer.x_only_public_key().0,
            &[deprecated_signer(old_signer.public_key())],
        );

        assert_eq!(candidates.len(), 2);
    }
}
