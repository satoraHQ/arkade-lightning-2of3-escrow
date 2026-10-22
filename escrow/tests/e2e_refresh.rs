//! Refresh e2e tests against a live arkd (see `just e2e`).

#![allow(clippy::unwrap_used)]

mod support;

use anyhow::{Context, Result};
use ark_escrow::contract::SignerSet;
use ark_escrow::refresh;
use bitcoin::key::{Keypair, Secp256k1};
use rand::thread_rng;
use support::regtest::{
    ESCROW_AMOUNT, REGTEST_LOCK, connect_escrow_client, fund_escrow, wait_for_exact_contract_amount,
};

/// A refresh intent registered by an earlier attempt that never joined a
/// batch holds the inputs. The next attempt must delete it and go on.
#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn refresh_clears_a_stale_intent_left_by_an_abandoned_attempt() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let (vtxos, _) = client.find_refresh_vtxos(&escrow.contract).await?;
    assert!(vtxos.iter().any(|v| v.amount == ESCROW_AMOUNT));

    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // Attempt 1: sign and register, then walk away (process died).
    let abandoned_cosigner = Keypair::new(&secp, &mut rng);
    let mut abandoned = client
        .prepare_refresh(
            &escrow.contract,
            &vtxos,
            SignerSet::BuyerArbiter,
            abandoned_cosigner.public_key(),
        )
        .await?;
    refresh::sign_refresh(&mut abandoned, &escrow.parties.buyer)?;
    refresh::sign_refresh(&mut abandoned, &escrow.parties.arbiter)?;
    let stale_id = client
        .grpc()
        .register_intent(abandoned.intent.clone())
        .await
        .context("registering the intent to abandon")?;
    eprintln!("abandoned intent {stale_id}");

    // Attempt 2: a fresh refresh, which must hit "already registered",
    // delete the stale intent with its own delete proof, and complete.
    let cosigner = Keypair::new(&secp, &mut rng);
    let mut fresh = client
        .prepare_refresh(
            &escrow.contract,
            &vtxos,
            SignerSet::BuyerArbiter,
            cosigner.public_key(),
        )
        .await?;
    let delete = fresh.delete_intent.as_ref().expect("delete proof prepared");
    let message: serde_json::Value = serde_json::from_str(&delete.serialize_message()?)?;
    assert_eq!(message["type"], "delete");
    let expire_at = message["expire_at"].as_u64().expect("expire_at");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    assert!(expire_at > now && expire_at <= now + 24 * 60 * 60 + 60);
    refresh::sign_refresh(&mut fresh, &escrow.parties.buyer)?;
    refresh::sign_refresh(&mut fresh, &escrow.parties.arbiter)?;

    // Proof that the stale intent really is in the way: arkd refuses a
    // plain registration of the fresh intent.
    let rejected = client
        .grpc()
        .register_intent(fresh.intent.clone())
        .await
        .expect_err("arkd must reject a second intent over the same inputs");
    let rejected = anyhow::anyhow!("{rejected:#}");
    eprintln!("arkd on second registration: {rejected:#}");
    assert!(
        refresh::is_stale_intent_error(&rejected),
        "unexpected rejection text: {rejected:#}"
    );

    // arkd refuses to register while the stale intent is queued (asserted
    // above), so a successful refresh is only possible if the client deleted
    // it first.
    client
        .refresh_escrow(fresh, cosigner)
        .await
        .context("refresh with a stale intent in the way")?;

    wait_for_exact_contract_amount(&client, &escrow.contract, ESCROW_AMOUNT)
        .await
        .context("refreshed escrow VTXO did not reappear")?;
    Ok(())
}

/// Without a stale intent the delete proof is never needed, and the refresh
/// behaves as before.
#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn refresh_without_a_stale_intent_still_completes() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;
    let (vtxos, _) = client.find_refresh_vtxos(&escrow.contract).await?;

    let cosigner = Keypair::new(&Secp256k1::new(), &mut thread_rng());
    let mut fresh = client
        .prepare_refresh(
            &escrow.contract,
            &vtxos,
            SignerSet::BuyerArbiter,
            cosigner.public_key(),
        )
        .await?;
    refresh::sign_refresh(&mut fresh, &escrow.parties.buyer)?;
    refresh::sign_refresh(&mut fresh, &escrow.parties.arbiter)?;
    client.refresh_escrow(fresh, cosigner).await?;

    wait_for_exact_contract_amount(&client, &escrow.contract, ESCROW_AMOUNT)
        .await
        .context("refreshed escrow VTXO did not reappear")?;
    Ok(())
}
