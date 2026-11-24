//! `verify_escrow_vtxo` against a live arkd, with Bitcoin read from the regtest esplora
//! (see `just e2e`).

#![allow(clippy::unwrap_used)]

mod support;

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use ark_core::VTXO_CONDITION_KEY;
use ark_core::send::{
    OffchainTransactions, SendReceiver, VtxoInput, build_offchain_transactions,
    sign_ark_transaction, sign_checkpoint_transaction,
};
use ark_core::server::GetVtxosRequest;
use ark_core::vhtlc::{VhtlcOptions, VhtlcScript};
use ark_core::{ArkAddress, VtxoList};
use ark_escrow::client::EscrowClient;
use ark_escrow::contract::EscrowContract;
use ark_escrow::verify::{BitcoinView, ExitPath, L1Output};
use bitcoin::hashes::{Hash, ripemd160, sha256};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::taproot::LeafVersion;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid, psbt};
use rand::thread_rng;
use support::regtest::{
    ArkCliWallet, ESCROW_AMOUNT, Parties, REGTEST_LOCK, connect_escrow_client, fund_escrow,
    wait_for_exact_contract_amount,
};

#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn verifies_a_wallet_deposit_against_bitcoin() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let escrow = fund_escrow(&client).await?;

    let path = verify(
        &client,
        &escrow.contract,
        escrow.vtxo.outpoint,
        ESCROW_AMOUNT,
    )
    .await?;
    println!("wallet deposit: {path:?}");
    ensure!(!path.anchors.is_empty(), "no anchors");

    let wrong = verify(
        &client,
        &escrow.contract,
        escrow.vtxo.outpoint,
        ESCROW_AMOUNT + Amount::ONE_SAT,
    )
    .await
    .expect_err("a different amount must not verify");
    ensure!(
        format!("{wrong:#}").contains("not the expected"),
        "{wrong:#}"
    );
    Ok(())
}

/// The Lightning deposit path: a VHTLC claimed with its preimage straight into the escrow, the
/// way a reverse swap pays the escrow address. The claim leaf is hash-locked, so this only
/// verifies if the indexer hands back the preimage the claim filed in the PSBT.
#[tokio::test]
#[ignore = "requires local arkade regtest stack"]
async fn verifies_a_deposit_claimed_from_a_vhtlc() -> Result<()> {
    let _guard = REGTEST_LOCK.lock().await;
    let client = connect_escrow_client().await?;
    let info = client.server_info()?;
    let secp = Secp256k1::new();

    let sender = Keypair::new(&secp, &mut thread_rng());
    let receiver = Keypair::new(&secp, &mut thread_rng());
    let preimage: [u8; 32] = rand::random();
    let preimage_hash = ripemd160::Hash::hash(sha256::Hash::hash(&preimage).as_byte_array());
    let delay = Sequence::from_seconds_ceil(512).unwrap();
    let vhtlc = VhtlcScript::new(
        VhtlcOptions {
            sender: sender.x_only_public_key().0,
            receiver: receiver.x_only_public_key().0,
            server: info.signer_pk.x_only_public_key().0,
            preimage_hash,
            refund_locktime: now()? + 3_600,
            unilateral_claim_delay: delay,
            unilateral_refund_delay: delay,
            unilateral_refund_without_receiver_delay: delay,
        },
        info.network,
    )?;

    let funding_wallet = ArkCliWallet::new(Amount::from_sat(1_000_000))?;
    funding_wallet.send(vhtlc.address().to_string(), ESCROW_AMOUNT)?;
    let vhtlc_outpoint = wait_for_vtxo(&client, vhtlc.address(), ESCROW_AMOUNT).await?;

    let parties = Parties::random();
    let contract = parties.contract(&client)?;
    let escrow_address = contract.address();

    let claim_script = vhtlc.claim_script();
    let control_block = vhtlc
        .taproot_spend_info()
        .control_block(&(claim_script.clone(), LeafVersion::TapScript))
        .context("claim leaf control block")?;
    let vhtlc_script_pubkey = vhtlc.script_pubkey();
    let input = VtxoInput::new(
        claim_script,
        None,
        control_block,
        vhtlc.tapscripts(),
        vhtlc_script_pubkey,
        ESCROW_AMOUNT,
        vhtlc_outpoint,
        Vec::new(),
    );
    let OffchainTransactions {
        mut ark_tx,
        checkpoint_txs,
    } = build_offchain_transactions(
        &[SendReceiver::bitcoin(escrow_address, ESCROW_AMOUNT)],
        &escrow_address,
        std::slice::from_ref(&input),
        &info,
    )?;

    let sign = |input: &mut psbt::Input, msg: bitcoin::secp256k1::Message| {
        input.unknown.insert(
            psbt::raw::Key {
                type_value: 222,
                key: VTXO_CONDITION_KEY.to_vec(),
            },
            bitcoin::consensus::serialize(&vec![preimage.to_vec()]),
        );
        let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, &receiver);
        Ok(vec![(sig, receiver.x_only_public_key().0)])
    };
    sign_ark_transaction(sign, &mut ark_tx, 0)?;
    let ark_txid = ark_tx.unsigned_tx.compute_txid();

    let res = client
        .grpc()
        .submit_offchain_transaction_request(ark_tx, checkpoint_txs)
        .await
        .context("submitting the VHTLC claim")?;
    let mut checkpoint = res
        .signed_checkpoint_txs
        .first()
        .context("no checkpoint returned")?
        .clone();
    sign_checkpoint_transaction(sign, &mut checkpoint)?;
    client
        .grpc()
        .finalize_offchain_transaction(ark_txid, vec![checkpoint])
        .await
        .context("finalizing the VHTLC claim")?;

    wait_for_exact_contract_amount(&client, &contract, ESCROW_AMOUNT).await?;
    let escrow_outpoint = OutPoint::new(ark_txid, 0);

    let path = verify(&client, &contract, escrow_outpoint, ESCROW_AMOUNT).await?;
    println!("VHTLC deposit: {path:?}");
    ensure!(!path.anchors.is_empty(), "no anchors");
    Ok(())
}

/// Read what Bitcoin holds for the VTXO's commitment transactions and verify the VTXO against it.
async fn verify(
    client: &EscrowClient,
    contract: &EscrowContract,
    outpoint: OutPoint,
    amount: Amount,
) -> Result<ExitPath> {
    let status = client
        .find_escrow_vtxo_statuses(contract)
        .await?
        .into_iter()
        .find(|v| v.outpoint == outpoint)
        .context("escrow VTXO not listed")?;

    let esplora = Esplora::new();
    let mut outputs = HashMap::new();
    for txid in &status.commitment_txids {
        esplora.wait_confirmed(*txid).await?;
        outputs.extend(esplora.outputs(*txid).await?);
    }
    let (height, median_time_past) = esplora.tip().await?;

    client
        .verify_escrow_vtxo(
            contract,
            outpoint,
            amount,
            &BitcoinView {
                outputs,
                height,
                median_time_past,
            },
        )
        .await
}

async fn wait_for_vtxo(
    client: &EscrowClient,
    address: ArkAddress,
    amount: Amount,
) -> Result<OutPoint> {
    let info = client.server_info()?;
    for _ in 0..60 {
        let request = GetVtxosRequest::new_for_addresses(std::iter::once(address));
        let response = client.grpc().list_vtxos(request).await?;
        let list = VtxoList::new(info.dust, response.vtxos);
        if let Some(vtxo) = list.all_unspent().find(|v| v.amount == amount) {
            return Ok(vtxo.outpoint);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("timed out waiting for {amount} at {address}")
}

fn now() -> Result<u32> {
    Ok(u32::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

/// The regtest stack's esplora, standing in for the caller's own Bitcoin source.
struct Esplora {
    http: reqwest::Client,
    base: String,
}

impl Esplora {
    fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            base: std::env::var("ESPLORA_URL")
                .unwrap_or_else(|_| "http://localhost:3000/api".to_string()),
        }
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.base);
        self.http
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?
            .json()
            .await
            .with_context(|| format!("GET {url}"))
    }

    async fn wait_confirmed(&self, txid: Txid) -> Result<()> {
        for _ in 0..60 {
            if let Ok(status) = self.get(&format!("/tx/{txid}/status")).await
                && status["confirmed"].as_bool() == Some(true)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("commitment transaction {txid} did not confirm")
    }

    async fn outputs(&self, txid: Txid) -> Result<HashMap<OutPoint, L1Output>> {
        let tx = self.get(&format!("/tx/{txid}")).await?;
        let outspends = self.get(&format!("/tx/{txid}/outspends")).await?;
        let vouts = tx["vout"].as_array().context("tx has no vout")?;

        vouts
            .iter()
            .enumerate()
            .map(|(vout, out)| {
                let script = ScriptBuf::from_hex(out["scriptpubkey"].as_str().context("script")?)?;
                let value = Amount::from_sat(out["value"].as_u64().context("value")?);
                let spend = &outspends[vout];
                let spent_by = match (
                    spend["spent"].as_bool(),
                    spend["status"]["confirmed"].as_bool(),
                ) {
                    (Some(true), Some(true)) => {
                        Some(spend["txid"].as_str().context("spender")?.parse()?)
                    }
                    _ => None,
                };
                Ok((
                    OutPoint::new(txid, vout as u32),
                    L1Output {
                        txout: TxOut {
                            value,
                            script_pubkey: script,
                        },
                        spent_by,
                    },
                ))
            })
            .collect()
    }

    async fn tip(&self) -> Result<(u32, u32)> {
        let hash = self
            .http
            .get(format!("{}/blocks/tip/hash", self.base))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let block = self.get(&format!("/block/{hash}")).await?;
        Ok((
            block["height"].as_u64().context("height")? as u32,
            block["mediantime"].as_u64().context("mediantime")? as u32,
        ))
    }
}
