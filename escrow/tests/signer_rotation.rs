#![allow(clippy::unwrap_used)]

mod support;

use anyhow::{Context, Result};
use ark_escrow::contract::EscrowOptions;
use ark_escrow::contract::{EscrowContract, SignerSet};
use ark_escrow::refresh;
use ark_escrow::spend;
use bitcoin::Amount;
use bitcoin::key::{Keypair, Secp256k1};
use rand::thread_rng;
use support::regtest::{
    ArkCliWallet, REGTEST_LOCK, connect_escrow_client, run_regtest, sign_checkpoints,
    temp_spend_store, wait_for_exact_contract_amount,
};

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn signer_rotation_refreshes_escrow_to_active_signer() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let client = connect_escrow_client().await?;
    let old_info = client.server_info()?;
    let funding_wallet = ArkCliWallet::new(Amount::from_sat(1_000_000))?;
    assert_eq!(funding_wallet.signer_pubkey()?, old_info.signer_pk);

    let seller_kp = Keypair::new(&secp, &mut rng);
    let buyer_kp = Keypair::new(&secp, &mut rng);
    let arbiter_kp = Keypair::new(&secp, &mut rng);

    let old_contract = EscrowContract::new(
        EscrowOptions {
            seller: seller_kp.x_only_public_key().0,
            buyer: buyer_kp.x_only_public_key().0,
            arbiter: arbiter_kp.x_only_public_key().0,
            server: old_info.signer_pk.into(),
            unilateral_exit_delay: old_info.unilateral_exit_delay,
        },
        old_info.network,
    )?;

    let escrow_amount = Amount::from_sat(100_000);
    funding_wallet.send(old_contract.address().to_string(), escrow_amount)?;

    wait_for_exact_contract_amount(&client, &old_contract, escrow_amount)
        .await
        .context("old-signer escrow VTXO was not visible before rotation")?;

    run_regtest(&["rotate-signer", "--cutoff", "+86400"])?;

    // Reconnect after arkd restarts and reconstruct the escrow with only the new/current signer,
    // simulating a consumer that did not persist the old signer key.
    let client = connect_escrow_client().await?;
    let new_info = client.server_info()?;
    assert_ne!(old_info.signer_pk, new_info.signer_pk);
    assert!(!new_info.deprecated_signers.is_empty());

    let mut current_options = old_contract.options().clone();
    current_options.server = new_info.signer_pk.into();
    let current_contract = EscrowContract::new(current_options, new_info.network)?;

    // The public lookup should still find the old-signer VTXO through deprecated_signers.
    let spendable = client
        .find_spendable_escrow_vtxos(&current_contract)
        .await?;
    assert!(
        spendable.iter().any(|v| v.amount == escrow_amount),
        "current-signer contract should resolve the old escrow VTXO via deprecated signers",
    );

    let (refresh_vtxos, _) = client.find_refresh_vtxos(&current_contract).await?;
    assert!(
        refresh_vtxos.iter().any(|v| v.amount == escrow_amount),
        "refresh VTXOs should include the old escrow VTXO: {refresh_vtxos:?}",
    );

    let cosigner_kp = Keypair::new(&secp, &mut rng);
    let mut refresh_intent = client
        .prepare_refresh(
            &current_contract,
            &refresh_vtxos,
            SignerSet::BuyerArbiter,
            cosigner_kp.public_key(),
        )
        .await?;
    refresh::sign_refresh(&mut refresh_intent, &buyer_kp)?;
    refresh::sign_refresh(&mut refresh_intent, &arbiter_kp)?;

    client.refresh_escrow(refresh_intent, cosigner_kp).await?;

    wait_for_exact_contract_amount(&client, &current_contract, escrow_amount)
        .await
        .context("refreshed escrow VTXO did not appear at the active-signer contract")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn signer_rotation_spends_old_escrow_offchain_with_current_contract_hint() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let client = connect_escrow_client().await?;
    let old_info = client.server_info()?;
    let funding_wallet = ArkCliWallet::new(Amount::from_sat(1_000_000))?;
    assert_eq!(funding_wallet.signer_pubkey()?, old_info.signer_pk);

    let seller_kp = Keypair::new(&secp, &mut rng);
    let buyer_kp = Keypair::new(&secp, &mut rng);
    let arbiter_kp = Keypair::new(&secp, &mut rng);

    let old_contract = EscrowContract::new(
        EscrowOptions {
            seller: seller_kp.x_only_public_key().0,
            buyer: buyer_kp.x_only_public_key().0,
            arbiter: arbiter_kp.x_only_public_key().0,
            server: old_info.signer_pk.into(),
            unilateral_exit_delay: old_info.unilateral_exit_delay,
        },
        old_info.network,
    )?;

    let escrow_amount = Amount::from_sat(100_000);
    funding_wallet.send(old_contract.address().to_string(), escrow_amount)?;

    wait_for_exact_contract_amount(&client, &old_contract, escrow_amount)
        .await
        .context("old-signer escrow VTXO was not visible before rotation")?;

    run_regtest(&["rotate-signer", "--cutoff", "+86400"])?;

    let client = connect_escrow_client().await?;
    let new_info = client.server_info()?;
    assert_ne!(old_info.signer_pk, new_info.signer_pk);
    assert!(!new_info.deprecated_signers.is_empty());

    let mut current_options = old_contract.options().clone();
    current_options.server = new_info.signer_pk.into();
    let current_contract = EscrowContract::new(current_options, new_info.network)?;

    let escrow_vtxo = client
        .find_spendable_escrow_vtxos(&current_contract)
        .await?
        .into_iter()
        .find(|v| v.amount == escrow_amount)
        .context("current-signer contract did not resolve old-signer escrow VTXO")?;

    let release = client
        .build_release_for_outpoint(
            &current_contract,
            escrow_vtxo.outpoint,
            &current_contract.address(),
            &[],
            SignerSet::BuyerArbiter,
        )
        .await?;

    let mut merged_ark_tx = release.ark_tx.clone();
    spend::sign_ark_tx(&mut merged_ark_tx, &buyer_kp)?;
    let mut arbiter_ark_tx = release.ark_tx.clone();
    spend::sign_ark_tx(&mut arbiter_ark_tx, &arbiter_kp)?;
    spend::merge_ark_tx_sigs(&mut merged_ark_tx, &arbiter_ark_tx)?;

    let buyer_checkpoints = sign_checkpoints(&release.checkpoint_txs, &buyer_kp)?;
    let arbiter_checkpoints = sign_checkpoints(&release.checkpoint_txs, &arbiter_kp)?;
    let store = temp_spend_store()?;
    let spend_id = format!("signer-rotation-offchain-{}", escrow_vtxo.outpoint);

    client
        .spend_escrow_offchain(
            &store,
            &spend_id,
            merged_ark_tx,
            release.checkpoint_txs,
            &[&buyer_checkpoints, &arbiter_checkpoints],
        )
        .await?;

    wait_for_exact_contract_amount(&client, &current_contract, escrow_amount)
        .await
        .context("offchain-spent escrow VTXO did not appear at the active-signer contract")?;

    Ok(())
}
