#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ark_core::VtxoList;
use ark_core::server::GetVtxosRequest;
use ark_escrow::client::EscrowClient;
use ark_escrow::contract::{EscrowContract, EscrowOptions, SignerSet};
use ark_escrow::refresh;
use ark_escrow::spend;
use ark_escrow::spend_store::FileSpendStore;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Psbt};
use rand::thread_rng;

static REGTEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

async fn connect_escrow_client() -> Result<EscrowClient> {
    let url = std::env::var("ARKD_URL").unwrap_or_else(|_| "http://localhost:7070".to_string());

    let mut last_error = None;
    for _ in 0..30 {
        let mut client = EscrowClient::new(&url);
        client.set_timeout(Some(Duration::from_secs(10)));
        match client.connect().await {
            Ok(_) => return Ok(client),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to local arkd"))
        .context("connecting to local arkd"))
}

async fn wait_for_exact_contract_amount(
    client: &EscrowClient,
    contract: &EscrowContract,
    amount: Amount,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    loop {
        if exact_contract_has_amount(client, contract, amount).await? {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for {amount} at {}", contract.address());
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn exact_contract_has_amount(
    client: &EscrowClient,
    contract: &EscrowContract,
    amount: Amount,
) -> Result<bool> {
    let info = client.server_info()?;
    let request = GetVtxosRequest::new_for_addresses(std::iter::once(contract.address()));
    let response = client.grpc().list_vtxos(request).await?;
    let vtxo_list = VtxoList::new(info.dust, response.vtxos);

    Ok(vtxo_list.all_unspent().any(|v| v.amount == amount))
}

fn sign_checkpoints(checkpoints: &[Psbt], keypair: &Keypair) -> Result<Vec<Psbt>> {
    checkpoints
        .iter()
        .map(|checkpoint| {
            let mut checkpoint = checkpoint.clone();
            spend::sign_checkpoint(&mut checkpoint, keypair)?;
            Ok(checkpoint)
        })
        .collect()
}

fn temp_spend_store() -> Result<FileSpendStore> {
    FileSpendStore::new(
        std::env::temp_dir().join(format!("ark-escrow-signer-rotation-{}", unique_nonce()?)),
    )
}

struct ArkCliWallet {
    datadir: String,
}

impl ArkCliWallet {
    fn new(initial_amount: Amount) -> Result<Self> {
        let datadir = format!("/tmp/ark-escrow-signer-rotation-{}", unique_nonce()?);
        run_regtest(&[
            "ark",
            "--datadir",
            &datadir,
            "init",
            "--password",
            "secret",
            "--server-url",
            "http://localhost:7070",
            "--explorer",
            "http://mempool_web/api",
        ])?;

        let note_amount = initial_amount.to_sat().to_string();
        let note_output = run_regtest(&["arkd", "note", "--amount", &note_amount])?;
        let note_stdout = String::from_utf8(note_output.stdout).context("decoding note output")?;
        let note = note_stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| line.starts_with("arknote"))
            .context("arkd note output did not contain an ArkNote")?;

        run_regtest(&[
            "ark",
            "--datadir",
            &datadir,
            "redeem-notes",
            "-n",
            note,
            "--password",
            "secret",
        ])?;

        Ok(Self { datadir })
    }

    fn signer_pubkey(&self) -> Result<PublicKey> {
        let output = run_regtest(&["ark", "--datadir", &self.datadir, "config"])?;
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("parsing ark config")?;
        json.get("signer_pubkey")
            .and_then(serde_json::Value::as_str)
            .context("ark config missing signer_pubkey")?
            .parse()
            .context("parsing ark config signer_pubkey")
    }

    fn send(&self, address: String, amount: Amount) -> Result<()> {
        let amount = amount.to_sat().to_string();
        run_regtest(&[
            "ark",
            "--datadir",
            &self.datadir,
            "send",
            "--to",
            &address,
            "--amount",
            &amount,
            "--password",
            "secret",
        ])?;

        Ok(())
    }
}

fn unique_nonce() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("computing unique nonce")?
        .as_nanos())
}

fn run_regtest(args: &[&str]) -> Result<Output> {
    let output = run_regtest_allow_failure(args)?;
    if !output.status.success() {
        bail!(
            "regtest.mjs {} failed\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    Ok(output)
}

fn run_regtest_allow_failure(args: &[&str]) -> Result<Output> {
    let script = regtest_mjs_path()?;
    Command::new("node")
        .arg(&script)
        .args(args)
        .output()
        .with_context(|| format!("running node {} {}", script.display(), args.join(" ")))
}

fn regtest_mjs_path() -> Result<PathBuf> {
    let dir = std::env::var("REGTEST_DIR").context("REGTEST_DIR must point to ark-rs/regtest")?;
    Ok(PathBuf::from(dir).join("regtest.mjs"))
}
