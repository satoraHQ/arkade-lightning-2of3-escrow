//! Spend-path e2e tests against a live arkd (see `just e2e`).

#![allow(clippy::unwrap_used)]

mod support;

use anyhow::{Context, Result};
use ark_escrow::contract::SignerSet;
use ark_escrow::spend;
use ark_escrow::spend_store::{PendingSpend, SpendStage, SpendStore, psbt_to_base64};
use bitcoin::Psbt;
use support::regtest::{
    ESCROW_AMOUNT, Parties, REGTEST_LOCK, connect_escrow_client, fund_escrow, sign_spend,
    temp_spend_store, wait_for_exact_contract_amount,
};

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn release_pays_the_buyer_destination() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let destination = Parties::random().contract(&client)?;

    let release = client
        .build_release_for_outpoint(
            &escrow.contract,
            escrow.vtxo.outpoint,
            &destination.address(),
            &[],
            SignerSet::BuyerArbiter,
        )
        .await?;
    let signed = sign_spend(&release, &escrow.parties.buyer, &escrow.parties.arbiter)?;
    let store = temp_spend_store()?;

    let txid = client
        .spend_escrow_offchain(
            &store,
            "release",
            signed.merged_ark_tx.clone(),
            signed.unsigned_checkpoints,
            &[&signed.party_checkpoints[0], &signed.party_checkpoints[1]],
        )
        .await?;
    assert_eq!(txid, signed.merged_ark_tx.unsigned_tx.compute_txid());
    let record = store.load("release")?.context("finalized record kept")?;
    assert_eq!(record.stage, SpendStage::Finalized);
    assert!(record.server_signed_ark_tx.is_some());

    wait_for_exact_contract_amount(&client, &destination, ESCROW_AMOUNT)
        .await
        .context("released amount did not arrive at the buyer destination")?;
    assert!(
        client
            .find_spendable_escrow_vtxos(&escrow.contract)
            .await?
            .is_empty(),
        "escrow VTXO still spendable after release"
    );
    Ok(())
}

/// One-shot submit against the real server: checkpoints that go out with
/// both party signatures come back still carrying them, which is arkd's
/// way of saying it finalized within `SubmitTx`. The payout
/// arrives without any `FinalizeTx`.
#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn submit_with_signed_checkpoints_is_finalized_by_arkd() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let destination = Parties::random().contract(&client)?;

    let release = client
        .build_release_for_outpoint(
            &escrow.contract,
            escrow.vtxo.outpoint,
            &destination.address(),
            &[],
            SignerSet::BuyerArbiter,
        )
        .await?;
    let signed = sign_spend(&release, &escrow.parties.buyer, &escrow.parties.arbiter)?;

    let res = client
        .grpc()
        .submit_offchain_transaction_request(
            signed.merged_ark_tx.clone(),
            party_signed_checkpoints(&signed)?,
        )
        .await
        .context("one-shot submit")?;
    assert!(res.finalized, "arkd did not finalize on submit");
    for checkpoint in &res.signed_checkpoint_txs {
        spend::verify_checkpoint_fully_signed(checkpoint)?;
    }

    wait_for_exact_contract_amount(&client, &destination, ESCROW_AMOUNT)
        .await
        .context("released amount did not arrive at the buyer destination")?;
    Ok(())
}

/// The checkpoints as the client submits them: both parties' signatures
/// merged in.
fn party_signed_checkpoints(signed: &support::regtest::SignedSpend) -> Result<Vec<Psbt>> {
    let mut checkpoints = signed.unsigned_checkpoints.clone();
    for party in &signed.party_checkpoints {
        for (checkpoint, party_checkpoint) in checkpoints.iter_mut().zip(party) {
            spend::merge_ark_tx_sigs(checkpoint, party_checkpoint)?;
        }
    }
    Ok(checkpoints)
}

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn refund_pays_the_seller_destination() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let destination = Parties::random().contract(&client)?;

    let refund = client
        .build_refund_for_outpoint(
            &escrow.contract,
            escrow.vtxo.outpoint,
            &destination.address(),
            SignerSet::SellerArbiter,
        )
        .await?;
    let signed = sign_spend(&refund, &escrow.parties.seller, &escrow.parties.arbiter)?;
    let store = temp_spend_store()?;

    client
        .spend_escrow_offchain(
            &store,
            "refund",
            signed.merged_ark_tx,
            signed.unsigned_checkpoints,
            &[&signed.party_checkpoints[0], &signed.party_checkpoints[1]],
        )
        .await?;

    wait_for_exact_contract_amount(&client, &destination, ESCROW_AMOUNT)
        .await
        .context("refunded amount did not arrive at the seller destination")?;
    Ok(())
}

/// The HH-ARK-023 scenario: the server accepted a submit whose response the
/// client never recorded (timeout, crash).
/// arkd answers the re-submit with `INVALID_ARK_PSBT: duplicated offchain tx
/// <txid>`; the client then reads the co-signed ark tx and the server-signed
/// checkpoints back from the indexer, verifies them and finalizes.
///
/// `one_shot` picks what the lost submit was: with party-signed checkpoints
/// arkd finalized it on the spot, with unsigned ones it is left pending.
async fn lost_submit_response_is_recovered(one_shot: bool) -> Result<()> {
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let destination = Parties::random().contract(&client)?;

    let release = client
        .build_release_for_outpoint(
            &escrow.contract,
            escrow.vtxo.outpoint,
            &destination.address(),
            &[],
            SignerSet::BuyerArbiter,
        )
        .await?;
    let signed = sign_spend(&release, &escrow.parties.buyer, &escrow.parties.arbiter)?;
    let ark_txid = signed.merged_ark_tx.unsigned_tx.compute_txid();

    // The "lost" submit: arkd accepts it; the response is never seen by the
    // store.
    let checkpoints = if one_shot {
        party_signed_checkpoints(&signed)?
    } else {
        signed.unsigned_checkpoints.clone()
    };
    let lost = client
        .grpc()
        .submit_offchain_transaction_request(signed.merged_ark_tx.clone(), checkpoints)
        .await
        .context("first (lost) submit")?;
    assert_eq!(lost.finalized, one_shot);

    // What the client had persisted before that submit went out.
    let store = temp_spend_store()?;
    store.save(&PendingSpend {
        id: "lost".to_string(),
        ark_txid: ark_txid.to_string(),
        signed_checkpoints: vec![],
        stage: SpendStage::Submitting,
        token: "attempt-1".to_string(),
        ark_tx: Some(psbt_to_base64(&signed.merged_ark_tx)),
        unsigned_checkpoints: signed
            .unsigned_checkpoints
            .iter()
            .map(psbt_to_base64)
            .collect(),
        party_signed_checkpoints: signed
            .party_checkpoints
            .iter()
            .map(|cps| cps.iter().map(psbt_to_base64).collect())
            .collect(),
        server_signed_ark_tx: None,
    })?;

    // The retry resumes the record, is told the server already holds the
    // transaction, and completes it.
    let txid = client
        .resume_pending_spend(&store, "lost")
        .await
        .context("resuming a spend the server already holds")?;
    assert_eq!(txid, Some(ark_txid));

    let record = store.load("lost")?.context("record kept")?;
    assert_eq!(record.stage, SpendStage::Finalized);
    assert_eq!(record.token, "attempt-1");
    assert!(record.server_signed_ark_tx.is_some());

    // The same on a first attempt, when the record was lost as well.
    let fresh = temp_spend_store()?;
    let txid = client
        .spend_escrow_offchain(
            &fresh,
            "lost-again",
            signed.merged_ark_tx.clone(),
            signed.unsigned_checkpoints.clone(),
            &[&signed.party_checkpoints[0], &signed.party_checkpoints[1]],
        )
        .await
        .context("first attempt for a spend the server already holds")?;
    assert_eq!(txid, ark_txid);
    assert_eq!(
        fresh.load("lost-again")?.context("record kept")?.stage,
        SpendStage::Finalized
    );

    wait_for_exact_contract_amount(&client, &destination, ESCROW_AMOUNT)
        .await
        .context("released amount did not arrive at the buyer destination")?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn lost_response_of_a_one_shot_submit_is_recovered() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    lost_submit_response_is_recovered(true).await
}

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn lost_response_of_a_pending_submit_is_recovered() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    lost_submit_response_is_recovered(false).await
}

/// Crash between `submit` and `finalize`: the record is at `submitted`,
/// `resume_pending_spend` finishes the job without a new submit.
#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn resume_after_crash_between_submit_and_finalize() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let destination = Parties::random().contract(&client)?;

    let release = client
        .build_release_for_outpoint(
            &escrow.contract,
            escrow.vtxo.outpoint,
            &destination.address(),
            &[],
            SignerSet::BuyerArbiter,
        )
        .await?;
    let signed = sign_spend(&release, &escrow.parties.buyer, &escrow.parties.arbiter)?;
    let ark_txid = signed.merged_ark_tx.unsigned_tx.compute_txid();

    // Submit exactly as the client does, then "crash" before finalize by
    // writing the record the client would have written and stopping.
    let res = client
        .grpc()
        .submit_offchain_transaction_request(
            signed.merged_ark_tx.clone(),
            signed.unsigned_checkpoints.clone(),
        )
        .await?;
    let final_checkpoints: Vec<_> = signed.party_checkpoints[0]
        .iter()
        .zip(&signed.party_checkpoints[1])
        .map(|(a, b)| {
            // Base on a party copy: it carries witness_script, which the
            // server strips.
            let mut cp = a.clone();
            spend::merge_ark_tx_sigs(&mut cp, b)?;
            let server_cp = res
                .signed_checkpoint_txs
                .iter()
                .find(|s| s.unsigned_tx == cp.unsigned_tx)
                .context("server did not return this checkpoint")?;
            spend::merge_ark_tx_sigs(&mut cp, server_cp)?;
            Ok(cp)
        })
        .collect::<Result<_>>()?;

    // The record carries the server's verified co-signature, as the client
    // writes it; a real arkd signature passes the leaf-key check.
    let cosigned_ark_tx =
        spend::verify_server_ark_tx_sig(&signed.merged_ark_tx, &res.signed_ark_tx)
            .context("arkd co-signature did not verify")?;

    let store = temp_spend_store()?;
    store.save(&PendingSpend {
        id: "crashed".to_string(),
        ark_txid: ark_txid.to_string(),
        signed_checkpoints: final_checkpoints.iter().map(psbt_to_base64).collect(),
        stage: SpendStage::Submitted,
        token: PendingSpend::new_token(),
        ark_tx: None,
        unsigned_checkpoints: vec![],
        party_signed_checkpoints: vec![],
        server_signed_ark_tx: Some(psbt_to_base64(&cosigned_ark_tx)),
    })?;

    let resumed = client.resume_pending_spend(&store, "crashed").await?;
    assert_eq!(resumed, Some(ark_txid));
    assert_eq!(
        store.load("crashed")?.context("record kept")?.stage,
        SpendStage::Finalized
    );

    wait_for_exact_contract_amount(&client, &destination, ESCROW_AMOUNT)
        .await
        .context("resumed release did not arrive at the destination")?;
    Ok(())
}
