//! Helpers for tests that run against a live arkade-regtest stack
//! (`REGTEST_DIR` must point at a checkout of arkade-regtest with
//! `regtest.mjs`; see `just e2e`).

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ark_core::VtxoList;
use ark_core::server::GetVtxosRequest;
use ark_escrow::client::EscrowClient;
use ark_escrow::contract::{EscrowContract, EscrowOptions};
use ark_escrow::spend::{self, EscrowVtxo};
use ark_escrow::spend_store::FileSpendStore;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Psbt};
use rand::thread_rng;

/// Serialises tests that share the one regtest stack.
pub static REGTEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub const ESCROW_AMOUNT: Amount = Amount::from_sat(100_000);

/// The three escrow parties of a test.
pub struct Parties {
    pub seller: Keypair,
    pub buyer: Keypair,
    pub arbiter: Keypair,
}

impl Parties {
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        Self {
            seller: Keypair::new(&secp, &mut rng),
            buyer: Keypair::new(&secp, &mut rng),
            arbiter: Keypair::new(&secp, &mut rng),
        }
    }

    pub fn contract(&self, client: &EscrowClient) -> Result<EscrowContract> {
        let info = client.server_info()?;
        EscrowContract::new(
            EscrowOptions {
                seller: self.seller.x_only_public_key().0,
                buyer: self.buyer.x_only_public_key().0,
                arbiter: self.arbiter.x_only_public_key().0,
                server: info.signer_pk.into(),
                unilateral_exit_delay: info.unilateral_exit_delay,
            },
            info.network,
        )
    }
}

/// A funded escrow at the current server key.
pub struct FundedEscrow {
    pub parties: Parties,
    pub contract: EscrowContract,
    pub vtxo: EscrowVtxo,
}

/// Fund a fresh escrow with [`ESCROW_AMOUNT`] from the regtest ark CLI
/// wallet and wait until arkd lists it.
pub async fn fund_escrow(client: &EscrowClient) -> Result<FundedEscrow> {
    let info = client.server_info()?;
    let funding_wallet = ArkCliWallet::new(Amount::from_sat(1_000_000))?;
    assert_eq!(funding_wallet.signer_pubkey()?, info.signer_pk);

    let parties = Parties::random();
    let contract = parties.contract(client)?;
    funding_wallet.send(contract.address().to_string(), ESCROW_AMOUNT)?;
    wait_for_exact_contract_amount(client, &contract, ESCROW_AMOUNT)
        .await
        .context("funded escrow VTXO did not become visible")?;

    let vtxo = client
        .find_spendable_escrow_vtxos(&contract)
        .await?
        .into_iter()
        .find(|v| v.amount == ESCROW_AMOUNT)
        .context("funded escrow VTXO not spendable")?;
    Ok(FundedEscrow {
        parties,
        contract,
        vtxo: EscrowVtxo {
            outpoint: vtxo.outpoint,
            amount: vtxo.amount,
        },
    })
}

/// Sign an unsigned escrow transaction with two parties, the way the
/// exchange does it: ark tx signatures merged into one PSBT, checkpoints
/// signed independently per party.
pub struct SignedSpend {
    pub merged_ark_tx: Psbt,
    pub unsigned_checkpoints: Vec<Psbt>,
    pub party_checkpoints: [Vec<Psbt>; 2],
}

pub fn sign_spend(tx: &spend::EscrowTransaction, a: &Keypair, b: &Keypair) -> Result<SignedSpend> {
    let mut merged_ark_tx = tx.ark_tx.clone();
    spend::sign_ark_tx(&mut merged_ark_tx, a)?;
    let mut other = tx.ark_tx.clone();
    spend::sign_ark_tx(&mut other, b)?;
    spend::merge_ark_tx_sigs(&mut merged_ark_tx, &other)?;
    Ok(SignedSpend {
        merged_ark_tx,
        unsigned_checkpoints: tx.checkpoint_txs.clone(),
        party_checkpoints: [
            sign_checkpoints(&tx.checkpoint_txs, a)?,
            sign_checkpoints(&tx.checkpoint_txs, b)?,
        ],
    })
}

pub async fn connect_escrow_client() -> Result<EscrowClient> {
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

pub async fn wait_for_exact_contract_amount(
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

pub fn sign_checkpoints(checkpoints: &[Psbt], keypair: &Keypair) -> Result<Vec<Psbt>> {
    checkpoints
        .iter()
        .map(|checkpoint| {
            let mut checkpoint = checkpoint.clone();
            spend::sign_checkpoint(&mut checkpoint, keypair)?;
            Ok(checkpoint)
        })
        .collect()
}

pub fn temp_spend_store() -> Result<FileSpendStore> {
    FileSpendStore::new(std::env::temp_dir().join(format!("ark-escrow-e2e-{}", unique_nonce()?)))
}

/// A wallet driven through the `ark` CLI inside the arkd container, funded
/// with a server credit note.
pub struct ArkCliWallet {
    datadir: String,
}

impl ArkCliWallet {
    pub fn new(initial_amount: Amount) -> Result<Self> {
        let datadir = format!("/tmp/ark-escrow-e2e-{}", unique_nonce()?);
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

    pub fn signer_pubkey(&self) -> Result<PublicKey> {
        let output = run_regtest(&["ark", "--datadir", &self.datadir, "config"])?;
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("parsing ark config")?;
        json.get("signer_pubkey")
            .and_then(serde_json::Value::as_str)
            .context("ark config missing signer_pubkey")?
            .parse()
            .context("parsing ark config signer_pubkey")
    }

    pub fn send(&self, address: String, amount: Amount) -> Result<()> {
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

pub fn unique_nonce() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("computing unique nonce")?
        .as_nanos())
}

pub fn run_regtest(args: &[&str]) -> Result<Output> {
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

pub fn run_regtest_allow_failure(args: &[&str]) -> Result<Output> {
    let script = regtest_mjs_path()?;
    Command::new("node")
        .arg(&script)
        .args(args)
        .output()
        .with_context(|| format!("running node {} {}", script.display(), args.join(" ")))
}

fn regtest_mjs_path() -> Result<PathBuf> {
    let dir = std::env::var("REGTEST_DIR")
        .context("REGTEST_DIR must point to an arkade-regtest checkout (see `just e2e`)")?;
    Ok(PathBuf::from(dir).join("regtest.mjs"))
}
