//! Proof that a VTXO the Arkade indexer reports is backed by Bitcoin.
//!
//! The indexer is the operator's own account of who owns what, so its word that an escrow is
//! funded is only as good as the operator (HH-ARK-111). What does not depend on it is the
//! unilateral-exit path: the presigned virtual transactions that lead from a batch output in a
//! commitment transaction down to the VTXO. Every transaction on that path is a real Bitcoin
//! transaction the owner could publish, so if each one is signed, spends its parent and ends in
//! an output paying the escrow, the VTXO is as real as the commitment output it starts from.
//!
//! What Bitcoin holds comes from the caller, read from Bitcoin rather than from the indexer, see
//! [`BitcoinView`]: the commitment outputs, who has spent them, and how far the chain has got. A
//! path that is signed but that Bitcoin would not take now, because an output on it went to another
//! transaction or a timelock has not run out, backs nothing. How deep the commitment transactions
//! must be buried stays the caller's decision, see [`ExitPath`].

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail, ensure};
use ark_core::VTXO_CONDITION_KEY;
use ark_core::server::VtxoChains;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, hash160};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_DROP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160,
    OP_VERIFY,
};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Message, Secp256k1, Verification};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxOut, Txid, XOnlyPublicKey, psbt,
};

/// More virtual transactions than any escrow deposit path has; bounds what the indexer can make
/// us walk.
pub const MAX_CHAIN_LEN: usize = 1_000;

/// Bitcoin's limit on a witness stack element in a tapscript spend.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// An output as the caller's Bitcoin node has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Output {
    pub txout: TxOut,
    /// The confirmed transaction spending this output, `None` while it is unspent.
    pub spent_by: Option<Txid>,
}

/// What the caller read from Bitcoin, the only part of a proof the indexer has no say in.
#[derive(Debug, Clone, Default)]
pub struct BitcoinView {
    /// Outputs of the VTXO's commitment transactions. Once a transaction of the VTXO's path is
    /// itself on Bitcoin, also the outputs of that transaction the path spends; verification
    /// names the ones it is missing.
    pub outputs: HashMap<OutPoint, L1Output>,
    /// Height of the chain tip.
    pub height: u32,
    /// Median time past of the chain tip, which is what Bitcoin holds time locks against.
    pub median_time_past: u32,
}

/// Where a verified VTXO's exit path meets Bitcoin.
///
/// The caller requires every anchor to be confirmed as deep as it sees fit. `spends` is what to
/// read from Bitcoin next time: the outputs whose spending decides whether the path stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPath {
    /// The Bitcoin outputs the path starts from, in commitment transactions.
    pub anchors: Vec<OutPoint>,
    /// Each output the path spends, anchors included, with the path transaction spending it.
    pub spends: Vec<(OutPoint, Txid)>,
}

/// Check that the VTXO at `outpoint`, paying `amount` to `script`, descends from Bitcoin outputs.
///
/// `chains` and `virtual_txs` are the indexer's `GetVtxoChain` and `GetVirtualTxs` answers for the
/// VTXO. `bitcoin` is what the caller read from Bitcoin.
/// `operator_keys` are the Arkade signer keys, current and deprecated: every VTXO spend on the
/// path must be cosigned by one of them, as an offchain spend always is. Without that, the owner
/// of a real VTXO could present a spend of it through the exit leaf alone and keep the VTXO.
///
/// Returns the path's footing on Bitcoin, so the caller can require confirmations on exactly
/// those.
pub fn verify_vtxo_chain(
    outpoint: OutPoint,
    script: &ScriptBuf,
    amount: Amount,
    chains: &VtxoChains,
    virtual_txs: &[Psbt],
    bitcoin: &BitcoinView,
    operator_keys: &[XOnlyPublicKey],
) -> Result<ExitPath> {
    // The path is walked recursively, so its length is bounded before the indexer can make it
    // arbitrarily deep.
    ensure!(
        chains.inner.len() <= MAX_CHAIN_LEN,
        "VTXO chain has {} transactions, more than {MAX_CHAIN_LEN}",
        chains.inner.len()
    );

    // Only the shape of the path is taken from the indexer's chain; every link is re-checked
    // against the transactions themselves below.
    let branch = ark_core::build_unilateral_exit_tree_txids(chains, outpoint.txid)
        .context("tracing the VTXO back to a commitment transaction")?
        .concat();

    // Keyed by the computed txid, so a transaction cannot stand in for another one.
    let by_txid: HashMap<Txid, &Psbt> = virtual_txs
        .iter()
        .map(|psbt| (psbt.unsigned_tx.compute_txid(), psbt))
        .collect();
    let branch_txs = branch
        .iter()
        .map(|txid| {
            by_txid
                .get(txid)
                .map(|psbt| (*txid, *psbt))
                .with_context(|| format!("indexer did not return virtual transaction {txid}"))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    let leaf = branch_txs
        .get(&outpoint.txid)
        .with_context(|| format!("VTXO transaction {} is not on its own path", outpoint.txid))?;
    let leaf_output = leaf
        .unsigned_tx
        .output
        .get(outpoint.vout as usize)
        .with_context(|| format!("VTXO output {outpoint} does not exist"))?;
    ensure!(
        leaf_output.script_pubkey == *script,
        "VTXO output {outpoint} pays {}, not the escrow script {script}",
        leaf_output.script_pubkey
    );
    ensure!(
        leaf_output.value == amount,
        "VTXO output {outpoint} is worth {}, not the expected {amount}",
        leaf_output.value
    );

    let secp = Secp256k1::verification_only();
    let mut anchors = Vec::new();
    let mut spends = Vec::new();
    let mut seen = HashSet::new();

    for txid in &branch {
        let psbt = branch_txs[txid];
        let mut prevouts = Vec::with_capacity(psbt.unsigned_tx.input.len());

        for input in &psbt.unsigned_tx.input {
            let spent = input.previous_output;
            // Bitcoin spends an output once: not twice in one transaction, and not in two
            // transactions of the same path.
            ensure!(
                seen.insert(spent),
                "{txid} spends {spent}, which the path already spends"
            );
            spends.push((spent, *txid));
            let prevout = match branch_txs.get(&spent.txid) {
                Some(parent) => parent.unsigned_tx.output.get(spent.vout as usize).cloned(),
                None => {
                    anchors.push(spent);
                    bitcoin.outputs.get(&spent).map(|o| o.txout.clone())
                }
            };
            prevouts.push(prevout.with_context(|| {
                format!("{txid} spends {spent}, which is neither on the VTXO's path nor a Bitcoin output")
            })?);
        }

        // A signature commits to the amounts it spends, but nothing stops a signed transaction
        // from paying out more than it has; Bitcoin would reject it, so this does too.
        let spent: Amount = prevouts.iter().map(|o| o.value).sum();
        let paid: Amount = psbt.unsigned_tx.output.iter().map(|o| o.value).sum();
        ensure!(
            paid <= spent,
            "virtual transaction {txid} has outputs worth {paid} but spends only {spent}"
        );

        for index in 0..prevouts.len() {
            verify_input(&secp, psbt, index, &prevouts, operator_keys)
                .with_context(|| format!("input {index} of virtual transaction {txid}"))?;
        }

        verify_publishable_now(&psbt.unsigned_tx, bitcoin)
            .with_context(|| format!("virtual transaction {txid}"))?;
    }

    verify_path_still_open(outpoint, &spends, bitcoin)?;

    anchors.sort();
    anchors.dedup();

    Ok(ExitPath { anchors, spends })
}

/// A transaction Bitcoin would not take yet is not a way out yet, whatever it is signed with.
fn verify_publishable_now(tx: &Transaction, bitcoin: &BitcoinView) -> Result<()> {
    // Honest path transactions never wait on their parent's age; one that does could be held
    // back until the batch has expired.
    ensure!(
        tx.input.iter().all(|i| !i.sequence.is_relative_lock_time()),
        "waits on a relative timelock"
    );

    let reached = match tx.lock_time {
        _ if !tx.is_lock_time_enabled() => true,
        LockTime::Blocks(height) => height.to_consensus_u32() <= bitcoin.height,
        LockTime::Seconds(time) => time.to_consensus_u32() < bitcoin.median_time_past,
    };
    ensure!(
        reached,
        "cannot be published before {}, and Bitcoin is at height {} and time {}",
        tx.lock_time,
        bitcoin.height,
        bitcoin.median_time_past
    );

    Ok(())
}

/// Check that nothing on Bitcoin has taken an output the path needs.
///
/// An output of the path may be spent only by the path's own transaction. Such a spend puts
/// that transaction on Bitcoin, and then its outputs are Bitcoin outputs too: what became of them
/// has to be known, down to the VTXO itself.
fn verify_path_still_open(
    vtxo: OutPoint,
    spends: &[(OutPoint, Txid)],
    bitcoin: &BitcoinView,
) -> Result<()> {
    let mut on_bitcoin = HashSet::new();

    for (spent, spender) in spends {
        match bitcoin.outputs.get(spent).and_then(|o| o.spent_by) {
            Some(by) if by == *spender => {
                on_bitcoin.insert(*spender);
            }
            Some(by) => bail!(
                "{spent} was spent on Bitcoin by {by}, not by {spender}: the VTXO has no exit path"
            ),
            None => {}
        }
    }

    let produced_on_bitcoin = spends
        .iter()
        .map(|(spent, _)| *spent)
        .chain([vtxo])
        .filter(|output| on_bitcoin.contains(&output.txid));
    for output in produced_on_bitcoin {
        ensure!(
            bitcoin.outputs.contains_key(&output),
            "{} is on Bitcoin, so what Bitcoin has for its output {output} is needed",
            output.txid
        );
    }

    if let Some(by) = bitcoin.outputs.get(&vtxo).and_then(|o| o.spent_by) {
        bail!("VTXO {vtxo} was spent on Bitcoin by {by}");
    }

    Ok(())
}

fn verify_input<C: Verification>(
    secp: &Secp256k1<C>,
    psbt: &Psbt,
    index: usize,
    prevouts: &[TxOut],
    operator_keys: &[XOnlyPublicKey],
) -> Result<()> {
    let input = psbt
        .inputs
        .get(index)
        .context("PSBT has no data for this input")?;
    let output_key = taproot_output_key(&prevouts[index].script_pubkey)?;
    let mut sighashes = SighashCache::new(&psbt.unsigned_tx);
    let prevouts = Prevouts::All(prevouts);

    // Batch-tree transactions spend their parent through the key path.
    if let Some(sig) = input.tap_key_sig {
        let sighash =
            sighashes.taproot_key_spend_signature_hash(index, &prevouts, sig.sighash_type)?;
        secp.verify_schnorr(
            &sig.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .context("key-path signature does not verify")?;
        return Ok(());
    }

    // Checkpoint and Ark transactions spend a VTXO through one of its tapleaves, cosigned by the
    // operator. The leaf has to be committed to, name the operator, carry a signature for every
    // CHECKSIG key, and have whatever else it asks for met by this transaction.
    for (control_block, (leaf_script, leaf_version)) in &input.tap_scripts {
        let pubkeys = ark_core::script::extract_checksig_pubkeys(leaf_script);
        if !pubkeys.iter().any(|pk| operator_keys.contains(pk))
            || !control_block.verify_taproot_commitment(secp, output_key, leaf_script)
        {
            continue;
        }

        let leaf_hash = TapLeafHash::from_script(leaf_script, *leaf_version);
        let Some(sigs) = pubkeys
            .iter()
            .map(|pk| {
                input
                    .tap_script_sigs
                    .get(&(*pk, leaf_hash))
                    .map(|sig| (pk, sig))
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };

        for (pk, sig) in sigs {
            let sighash = sighashes.taproot_script_spend_signature_hash(
                index,
                &prevouts,
                leaf_hash,
                sig.sighash_type,
            )?;
            secp.verify_schnorr(
                &sig.signature,
                &Message::from_digest(sighash.to_byte_array()),
                pk,
            )
            .with_context(|| format!("script-path signature by {pk} does not verify"))?;
        }

        return verify_leaf_conditions(leaf_script, psbt, index);
    }

    bail!("no tapleaf of the spent output is signed by its keys and the operator")
}

/// Check what a signed tapleaf asks for besides signatures, since Bitcoin rejects a spend whose
/// leaf is signed but not satisfied.
///
/// This is not a script interpreter. It knows the shapes Arkade's cosigned leaves are built
/// from: hash locks and absolute timelocks first, then the keys, `CHECKSIGVERIFY` for all but the
/// last. A leaf of any other shape is refused rather than assumed spendable.
fn verify_leaf_conditions(leaf_script: &ScriptBuf, psbt: &Psbt, index: usize) -> Result<()> {
    use Instruction::{Op, PushBytes};

    let instructions = leaf_script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .context("tapleaf is not a valid script")?;
    // The finalized witness carries these above the signatures, last element on top.
    let mut condition_witness = condition_witness(&psbt.inputs[index])?;
    let mut rest = instructions.as_slice();

    loop {
        rest = match rest {
            [
                Op(OP_HASH160),
                PushBytes(hash),
                Op(OP_EQUALVERIFY),
                tail @ ..,
            ]
            | [
                Op(OP_HASH160),
                PushBytes(hash),
                Op(OP_EQUAL),
                Op(OP_VERIFY),
                tail @ ..,
            ] => {
                let preimage = condition_witness
                    .pop()
                    .context("tapleaf is hash-locked and the spend has no preimage")?;
                ensure!(
                    preimage.len() <= MAX_SCRIPT_ELEMENT_SIZE,
                    "preimage is {} bytes, more than Bitcoin lets a witness element be",
                    preimage.len()
                );
                ensure!(
                    hash160::Hash::hash(&preimage).as_byte_array() == hash.as_bytes(),
                    "preimage does not open the tapleaf's hash lock"
                );
                tail
            }
            [locktime, Op(OP_CLTV), Op(OP_DROP), tail @ ..] => {
                let required = locktime
                    .script_num()
                    .and_then(|n| u32::try_from(n).ok())
                    .map(LockTime::from_consensus)
                    .context("tapleaf has a malformed timelock")?;
                let lock_time = psbt.unsigned_tx.lock_time;
                ensure!(
                    required.is_same_unit(lock_time)
                        && required.to_consensus_u32() <= lock_time.to_consensus_u32(),
                    "tapleaf is locked until {required} and the spend is valid from {lock_time}"
                );
                ensure!(
                    psbt.unsigned_tx.input[index].sequence != Sequence::MAX,
                    "tapleaf is timelocked and the spend's sequence disables timelocks"
                );
                tail
            }
            _ => break,
        };
    }
    ensure!(
        condition_witness.is_empty(),
        "spend carries witness elements its tapleaf does not consume"
    );

    loop {
        rest = match rest {
            [PushBytes(key), Op(OP_CHECKSIG)] if key.len() == 32 => return Ok(()),
            [PushBytes(key), Op(OP_CHECKSIGVERIFY), tail @ ..] if key.len() == 32 => tail,
            _ => bail!("tapleaf {leaf_script} has conditions this verifier cannot check"),
        };
    }
}

/// The extra witness elements a spend supplies for its leaf's conditions, such as a VHTLC
/// preimage, as Arkade files them in the PSBT.
fn condition_witness(input: &psbt::Input) -> Result<Vec<Vec<u8>>> {
    let key = psbt::raw::Key {
        type_value: 222,
        key: VTXO_CONDITION_KEY.to_vec(),
    };

    match input.unknown.get(&key) {
        Some(encoded) => bitcoin::consensus::deserialize(encoded)
            .context("condition witness in the PSBT is malformed"),
        None => Ok(Vec::new()),
    }
}

fn taproot_output_key(script: &ScriptBuf) -> Result<XOnlyPublicKey> {
    ensure!(script.is_p2tr(), "spent output {script} is not taproot");
    Ok(XOnlyPublicKey::from_slice(&script.as_bytes()[2..34])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_core::server::{ChainedTxType, VtxoChain};
    use bitcoin::TxIn;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::opcodes::all::OP_CSV;
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::All;
    use bitcoin::sighash::TapSighashType;
    use bitcoin::taproot::{self, LeafVersion, TaprootBuilder, TaprootSpendInfo};
    use bitcoin::transaction::Version;

    const VALUE: Amount = Amount::from_sat(10_000);
    const TIP_HEIGHT: u32 = 800_000;
    const TIP_TIME: u32 = 1_700_000_001;

    fn unspent(txout: TxOut) -> L1Output {
        L1Output {
            txout,
            spent_by: None,
        }
    }

    fn spent(txout: TxOut, by: Txid) -> L1Output {
        L1Output {
            txout,
            spent_by: Some(by),
        }
    }

    /// Commitment output -> batch-tree leaf (key path) -> Ark transaction (owner + operator
    /// tapleaf) paying the escrow, the shape of a preconfirmed escrow deposit.
    struct Fixture {
        secp: Secp256k1<All>,
        owner: Keypair,
        operator: Keypair,
        commitment: OutPoint,
        batch_output: TxOut,
        tree: Psbt,
        ark: Psbt,
        escrow_script: ScriptBuf,
        /// The tapleaf the Ark transaction spends the VTXO through.
        leaf: ScriptBuf,
    }

    impl Fixture {
        fn new() -> Self {
            Self::spending_through(|owner, operator| {
                Builder::new()
                    .push_x_only_key(&owner)
                    .push_opcode(OP_CHECKSIGVERIFY)
                    .push_x_only_key(&operator)
                    .push_opcode(OP_CHECKSIG)
                    .into_script()
            })
        }

        /// A deposit whose VTXO is spent through the leaf `leaf` builds from the owner's and the
        /// operator's keys.
        fn spending_through(
            leaf: impl FnOnce(XOnlyPublicKey, XOnlyPublicKey) -> ScriptBuf,
        ) -> Self {
            let secp = Secp256k1::new();
            let [cosigner, owner, operator, escrow] =
                std::array::from_fn(|_| Keypair::new(&secp, &mut rand::thread_rng()));

            let commitment = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
            let batch_output = TxOut {
                value: VALUE,
                script_pubkey: ScriptBuf::new_p2tr(&secp, cosigner.x_only_public_key().0, None),
            };
            let escrow_script = ScriptBuf::new_p2tr(&secp, escrow.x_only_public_key().0, None);

            let leaf = leaf(owner.x_only_public_key().0, operator.x_only_public_key().0);
            let vtxo_info = leaf_info(&secp, &owner, &leaf);
            let vtxo_output = TxOut {
                value: VALUE,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(vtxo_info.output_key()),
            };
            let tree = Psbt::from_unsigned_tx(tx(commitment, vtxo_output)).unwrap();
            let escrow_output = TxOut {
                value: VALUE,
                script_pubkey: escrow_script.clone(),
            };
            let vtxo = OutPoint::new(tree.unsigned_tx.compute_txid(), 0);
            let ark = Psbt::from_unsigned_tx(tx(vtxo, escrow_output)).unwrap();

            let mut fixture = Fixture {
                secp,
                owner,
                operator,
                commitment,
                batch_output,
                tree,
                ark,
                escrow_script,
                leaf,
            };
            fixture.sign_tree(&cosigner);
            fixture.sign_ark(&owner);
            fixture
        }

        fn tree_txid(&self) -> Txid {
            self.tree.unsigned_tx.compute_txid()
        }

        fn ark_txid(&self) -> Txid {
            self.ark.unsigned_tx.compute_txid()
        }

        fn sign_tree(&mut self, signer: &Keypair) {
            let prevouts = [self.batch_output.clone()];
            let sighash = SighashCache::new(&self.tree.unsigned_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();
            let tweaked = signer.tap_tweak(&self.secp, None).to_keypair();
            self.tree.inputs[0].tap_key_sig =
                Some(self.signature(sighash.to_byte_array(), &tweaked));
        }

        /// Sign the Ark transaction through the owner + operator leaf; `owner_signer` produces
        /// the signature filed under the owner's key.
        fn sign_ark(&mut self, owner_signer: &Keypair) {
            let script = self.leaf.clone();
            let info = leaf_info(&self.secp, &self.owner, &script);
            let control_block = info
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap();
            let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
            let prevouts = [self.tree.unsigned_tx.output[0].clone()];
            let sighash = SighashCache::new(&self.ark.unsigned_tx)
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .unwrap()
                .to_byte_array();

            let owner_sig = self.signature(sighash, owner_signer);
            let operator_sig = self.signature(sighash, &self.operator);
            let input = &mut self.ark.inputs[0];
            input.tap_script_sigs.clear();
            input
                .tap_scripts
                .insert(control_block, (script, LeafVersion::TapScript));
            input
                .tap_script_sigs
                .insert((self.owner.x_only_public_key().0, leaf_hash), owner_sig);
            input.tap_script_sigs.insert(
                (self.operator.x_only_public_key().0, leaf_hash),
                operator_sig,
            );
        }

        fn signature(&self, sighash: [u8; 32], signer: &Keypair) -> taproot::Signature {
            taproot::Signature {
                signature: self
                    .secp
                    .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), signer),
                sighash_type: TapSighashType::Default,
            }
        }

        fn chains(&self) -> VtxoChains {
            VtxoChains {
                inner: vec![
                    chain(self.commitment.txid, ChainedTxType::Commitment, vec![]),
                    chain(
                        self.tree_txid(),
                        ChainedTxType::Tree,
                        vec![self.commitment.txid],
                    ),
                    chain(self.ark_txid(), ChainedTxType::Ark, vec![self.tree_txid()]),
                ],
            }
        }

        fn l1_outputs(&self) -> HashMap<OutPoint, L1Output> {
            HashMap::from([(self.commitment, unspent(self.batch_output.clone()))])
        }

        fn txs(&self) -> Vec<Psbt> {
            vec![self.tree.clone(), self.ark.clone()]
        }

        fn operator_keys(&self) -> Vec<XOnlyPublicKey> {
            vec![self.operator.x_only_public_key().0]
        }

        fn verify(&self) -> Result<ExitPath> {
            self.verify_with(&self.txs(), &self.l1_outputs())
        }

        fn verify_with(
            &self,
            txs: &[Psbt],
            l1_outputs: &HashMap<OutPoint, L1Output>,
        ) -> Result<ExitPath> {
            self.verify_vtxo(
                &self.escrow_script,
                VALUE,
                txs,
                l1_outputs,
                &self.operator_keys(),
            )
        }

        fn verify_vtxo(
            &self,
            script: &ScriptBuf,
            amount: Amount,
            txs: &[Psbt],
            l1_outputs: &HashMap<OutPoint, L1Output>,
            operator_keys: &[XOnlyPublicKey],
        ) -> Result<ExitPath> {
            verify_vtxo_chain(
                OutPoint::new(self.ark_txid(), 0),
                script,
                amount,
                &self.chains(),
                txs,
                &BitcoinView {
                    outputs: l1_outputs.clone(),
                    height: TIP_HEIGHT,
                    median_time_past: TIP_TIME,
                },
                operator_keys,
            )
        }
    }

    /// The collaborative leaf of a VTXO: owner and operator both sign.
    fn vtxo_leaf(
        secp: &Secp256k1<All>,
        owner: &Keypair,
        operator: &Keypair,
    ) -> (ScriptBuf, TaprootSpendInfo) {
        let script = Builder::new()
            .push_x_only_key(&owner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&operator.x_only_public_key().0)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let info = leaf_info(secp, owner, &script);
        (script, info)
    }

    fn leaf_info(secp: &Secp256k1<All>, owner: &Keypair, script: &ScriptBuf) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(secp, owner.x_only_public_key().0)
            .unwrap()
    }

    /// `conditions`, then the owner's and the operator's signatures.
    fn conditional_leaf(
        conditions: Builder,
    ) -> impl FnOnce(XOnlyPublicKey, XOnlyPublicKey) -> ScriptBuf {
        move |owner, operator| {
            conditions
                .push_x_only_key(&owner)
                .push_opcode(OP_CHECKSIGVERIFY)
                .push_x_only_key(&operator)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        }
    }

    fn hash_lock(preimage: &[u8]) -> Builder {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(hash160::Hash::hash(preimage).to_byte_array())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_VERIFY)
    }

    fn timelock(height: i64) -> Builder {
        Builder::new()
            .push_int(height)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
    }

    fn reveal(fixture: &mut Fixture, preimage: &[u8]) {
        fixture.ark.inputs[0].unknown.insert(
            psbt::raw::Key {
                type_value: 222,
                key: VTXO_CONDITION_KEY.to_vec(),
            },
            bitcoin::consensus::serialize(&vec![preimage.to_vec()]),
        );
    }

    /// Set the Ark transaction's locktime and sign it again, as the locktime is signed over.
    fn spend_at(fixture: &mut Fixture, height: u32, sequence: Sequence) {
        fixture.ark.unsigned_tx.lock_time = LockTime::from_consensus(height);
        fixture.ark.unsigned_tx.input[0].sequence = sequence;
        let owner = fixture.owner;
        fixture.sign_ark(&owner);
    }

    fn tx(spent: OutPoint, output: TxOut) -> Transaction {
        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent,
                ..TxIn::default()
            }],
            output: vec![output],
        }
    }

    fn chain(txid: Txid, tx_type: ChainedTxType, spends: Vec<Txid>) -> VtxoChain {
        VtxoChain {
            txid,
            tx_type,
            spends,
            expires_at: 0,
        }
    }

    fn assert_rejected(result: Result<ExitPath>, reason: &str) {
        let error = format!("{:#}", result.expect_err("chain should be rejected"));
        assert!(error.contains(reason), "{error}");
    }

    fn stranger(fixture: &Fixture) -> Keypair {
        Keypair::new(&fixture.secp, &mut rand::thread_rng())
    }

    #[test]
    fn accepts_a_signed_path_from_a_bitcoin_output() {
        let fixture = Fixture::new();

        assert_eq!(fixture.verify().unwrap().anchors, vec![fixture.commitment]);
    }

    #[test]
    fn names_the_transaction_allowed_to_spend_each_output_on_the_path() {
        let fixture = Fixture::new();

        assert_eq!(
            fixture.verify().unwrap().spends,
            vec![
                (fixture.commitment, fixture.tree_txid()),
                (OutPoint::new(fixture.tree_txid(), 0), fixture.ark_txid()),
            ]
        );
    }

    #[test]
    fn rejects_a_vtxo_paying_another_script() {
        let fixture = Fixture::new();
        let foreign = ScriptBuf::new_p2tr(&fixture.secp, fixture.owner.x_only_public_key().0, None);

        let result = fixture.verify_vtxo(
            &foreign,
            VALUE,
            &fixture.txs(),
            &fixture.l1_outputs(),
            &fixture.operator_keys(),
        );

        assert_rejected(result, "not the escrow script");
    }

    #[test]
    fn rejects_an_amount_the_transaction_does_not_carry() {
        let fixture = Fixture::new();

        let result = fixture.verify_vtxo(
            &fixture.escrow_script,
            VALUE * 2,
            &fixture.txs(),
            &fixture.l1_outputs(),
            &fixture.operator_keys(),
        );

        assert_rejected(result, "not the expected");
    }

    #[test]
    fn rejects_a_path_not_rooted_in_a_known_bitcoin_output() {
        let fixture = Fixture::new();

        let result = fixture.verify_with(&fixture.txs(), &HashMap::new());

        assert_rejected(result, "nor a Bitcoin output");
    }

    #[test]
    fn rejects_a_batch_output_bitcoin_does_not_have() {
        let fixture = Fixture::new();
        let mut l1_outputs = fixture.l1_outputs();
        l1_outputs.insert(
            fixture.commitment,
            unspent(TxOut {
                value: VALUE,
                script_pubkey: fixture.escrow_script.clone(),
            }),
        );

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "key-path signature does not verify");
    }

    #[test]
    fn rejects_value_the_bitcoin_output_does_not_hold() {
        let fixture = Fixture::new();
        let mut l1_outputs = fixture.l1_outputs();
        l1_outputs.get_mut(&fixture.commitment).unwrap().txout.value = VALUE / 2;

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "spends only");
    }

    #[test]
    fn rejects_a_transaction_that_spends_an_output_twice() {
        let mut fixture = Fixture::new();
        let input = fixture.ark.unsigned_tx.input[0].clone();
        fixture.ark.unsigned_tx.input.push(input);
        let signed = fixture.ark.inputs[0].clone();
        fixture.ark.inputs.push(signed);

        assert_rejected(fixture.verify(), "already spends");
    }

    #[test]
    fn rejects_a_tree_transaction_signed_by_someone_else() {
        let mut fixture = Fixture::new();
        let stranger = stranger(&fixture);
        fixture.sign_tree(&stranger);

        assert_rejected(fixture.verify(), "key-path signature does not verify");
    }

    #[test]
    fn rejects_a_forged_vtxo_spend_signature() {
        let mut fixture = Fixture::new();
        let stranger = stranger(&fixture);
        fixture.sign_ark(&stranger);

        assert_rejected(fixture.verify(), "script-path signature by");
    }

    #[test]
    fn rejects_an_unsigned_vtxo_spend() {
        let mut fixture = Fixture::new();
        fixture.ark.inputs[0].tap_script_sigs.clear();

        assert_rejected(fixture.verify(), "no tapleaf");
    }

    #[test]
    fn rejects_a_vtxo_spend_the_operator_did_not_cosign() {
        let fixture = Fixture::new();
        let other_operator = stranger(&fixture).x_only_public_key().0;

        let result = fixture.verify_vtxo(
            &fixture.escrow_script,
            VALUE,
            &fixture.txs(),
            &fixture.l1_outputs(),
            &[other_operator],
        );

        assert_rejected(result, "no tapleaf");
    }

    #[test]
    fn rejects_a_leaf_the_spent_output_does_not_commit_to() {
        let mut fixture = Fixture::new();
        let (script, _) = vtxo_leaf(&fixture.secp, &fixture.owner, &fixture.operator);
        let (other_script, other_info) =
            vtxo_leaf(&fixture.secp, &stranger(&fixture), &fixture.operator);
        let other_block = other_info
            .control_block(&(other_script, LeafVersion::TapScript))
            .unwrap();
        let input = &mut fixture.ark.inputs[0];
        input.tap_scripts.clear();
        input
            .tap_scripts
            .insert(other_block, (script, LeafVersion::TapScript));

        assert_rejected(fixture.verify(), "no tapleaf");
    }

    #[test]
    fn rejects_a_path_the_indexer_did_not_hand_over() {
        let fixture = Fixture::new();

        let result = fixture.verify_with(std::slice::from_ref(&fixture.ark), &fixture.l1_outputs());

        assert_rejected(result, "did not return virtual transaction");
    }

    #[test]
    fn rejects_a_transaction_swapped_for_another() {
        let fixture = Fixture::new();
        let mut swapped = fixture.tree.clone();
        swapped.unsigned_tx.output[0].value = VALUE * 2;

        let result = fixture.verify_with(&[swapped, fixture.ark.clone()], &fixture.l1_outputs());

        assert_rejected(result, "did not return virtual transaction");
    }

    #[test]
    fn rejects_a_chain_longer_than_any_deposit_path() {
        let fixture = Fixture::new();
        let mut chains = fixture.chains();
        chains.inner.extend((0..MAX_CHAIN_LEN).map(|n| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            chain(Txid::from_byte_array(bytes), ChainedTxType::Ark, vec![])
        }));

        let result = verify_vtxo_chain(
            OutPoint::new(fixture.ark_txid(), 0),
            &fixture.escrow_script,
            VALUE,
            &chains,
            &fixture.txs(),
            &BitcoinView {
                outputs: fixture.l1_outputs(),
                height: TIP_HEIGHT,
                median_time_past: TIP_TIME,
            },
            &fixture.operator_keys(),
        );

        assert_rejected(result, "more than");
    }

    #[test]
    fn accepts_a_hash_locked_spend_that_reveals_the_preimage() {
        let mut fixture = Fixture::spending_through(conditional_leaf(hash_lock(b"secret")));
        reveal(&mut fixture, b"secret");

        assert_eq!(fixture.verify().unwrap().anchors, vec![fixture.commitment]);
    }

    #[test]
    fn rejects_a_hash_locked_spend_without_the_preimage() {
        let fixture = Fixture::spending_through(conditional_leaf(hash_lock(b"secret")));

        assert_rejected(fixture.verify(), "has no preimage");
    }

    #[test]
    fn rejects_a_hash_locked_spend_with_another_preimage() {
        let mut fixture = Fixture::spending_through(conditional_leaf(hash_lock(b"secret")));
        reveal(&mut fixture, b"guess");

        assert_rejected(fixture.verify(), "does not open");
    }

    #[test]
    fn rejects_a_preimage_too_long_for_a_witness() {
        let preimage = [7; MAX_SCRIPT_ELEMENT_SIZE + 1];
        let mut fixture = Fixture::spending_through(conditional_leaf(hash_lock(&preimage)));
        reveal(&mut fixture, &preimage);

        assert_rejected(fixture.verify(), "more than Bitcoin lets");
    }

    #[test]
    fn rejects_witness_elements_the_leaf_does_not_consume() {
        let mut fixture = Fixture::new();
        reveal(&mut fixture, b"secret");

        assert_rejected(fixture.verify(), "does not consume");
    }

    #[test]
    fn accepts_a_timelocked_spend_once_the_lock_has_passed() {
        let mut fixture = Fixture::spending_through(conditional_leaf(timelock(800_000)));
        spend_at(&mut fixture, 800_000, Sequence::ENABLE_LOCKTIME_NO_RBF);

        assert_eq!(fixture.verify().unwrap().anchors, vec![fixture.commitment]);
    }

    #[test]
    fn rejects_a_timelocked_spend_valid_before_the_lock() {
        let mut fixture = Fixture::spending_through(conditional_leaf(timelock(800_000)));
        spend_at(&mut fixture, 799_999, Sequence::ENABLE_LOCKTIME_NO_RBF);

        assert_rejected(fixture.verify(), "is locked until");
    }

    #[test]
    fn rejects_a_timelock_measured_in_another_unit() {
        let mut fixture = Fixture::spending_through(conditional_leaf(timelock(800_000)));
        spend_at(
            &mut fixture,
            1_700_000_000,
            Sequence::ENABLE_LOCKTIME_NO_RBF,
        );

        assert_rejected(fixture.verify(), "is locked until");
    }

    #[test]
    fn rejects_a_timelocked_spend_whose_sequence_disables_timelocks() {
        let mut fixture = Fixture::spending_through(conditional_leaf(timelock(800_000)));
        spend_at(&mut fixture, 800_000, Sequence::MAX);

        assert_rejected(fixture.verify(), "disables timelocks");
    }

    #[test]
    fn rejects_a_leaf_with_a_condition_it_cannot_check() {
        let relative_delay = Builder::new()
            .push_int(144)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);
        let fixture = Fixture::spending_through(conditional_leaf(relative_delay));

        assert_rejected(fixture.verify(), "cannot check");
    }

    #[test]
    fn rejects_a_leaf_that_leaves_more_than_one_result() {
        let fixture = Fixture::spending_through(|owner, operator| {
            Builder::new()
                .push_x_only_key(&owner)
                .push_opcode(OP_CHECKSIG)
                .push_x_only_key(&operator)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        });

        assert_rejected(fixture.verify(), "cannot check");
    }

    #[test]
    fn rejects_a_transaction_bitcoin_would_not_take_yet() {
        let mut fixture = Fixture::new();
        spend_at(
            &mut fixture,
            TIP_HEIGHT + 1,
            Sequence::ENABLE_LOCKTIME_NO_RBF,
        );

        assert_rejected(fixture.verify(), "cannot be published before");
    }

    #[test]
    fn rejects_a_time_lock_the_median_time_has_not_passed() {
        let mut fixture = Fixture::new();
        spend_at(&mut fixture, TIP_TIME, Sequence::ENABLE_LOCKTIME_NO_RBF);

        assert_rejected(fixture.verify(), "cannot be published before");
    }

    #[test]
    fn accepts_a_locktime_the_sequence_switches_off() {
        let mut fixture = Fixture::new();
        spend_at(&mut fixture, TIP_HEIGHT + 1, Sequence::MAX);

        assert_eq!(fixture.verify().unwrap().anchors, vec![fixture.commitment]);
    }

    #[test]
    fn rejects_a_transaction_that_waits_on_its_parents_age() {
        let mut fixture = Fixture::new();
        spend_at(&mut fixture, 0, Sequence::from_height(144));

        assert_rejected(fixture.verify(), "relative timelock");
    }

    #[test]
    fn rejects_a_batch_output_something_else_spent() {
        let fixture = Fixture::new();
        let mut l1_outputs = fixture.l1_outputs();
        l1_outputs.get_mut(&fixture.commitment).unwrap().spent_by =
            Some(Txid::from_byte_array([9; 32]));

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "has no exit path");
    }

    /// Bitcoin after the batch tree was published: the batch output went to the tree transaction,
    /// whose output is the VTXO the Ark transaction spends.
    fn unrolled(fixture: &Fixture, vtxo: L1Output) -> HashMap<OutPoint, L1Output> {
        HashMap::from([
            (
                fixture.commitment,
                spent(fixture.batch_output.clone(), fixture.tree_txid()),
            ),
            (OutPoint::new(fixture.tree_txid(), 0), vtxo),
        ])
    }

    #[test]
    fn accepts_a_path_partly_published_by_its_own_transactions() {
        let fixture = Fixture::new();
        let vtxo = unspent(fixture.tree.unsigned_tx.output[0].clone());

        let result = fixture.verify_with(&fixture.txs(), &unrolled(&fixture, vtxo));

        assert_eq!(result.unwrap().anchors, vec![fixture.commitment]);
    }

    #[test]
    fn rejects_a_published_output_its_owner_took_back() {
        let fixture = Fixture::new();
        let exit = Txid::from_byte_array([9; 32]);
        let vtxo = spent(fixture.tree.unsigned_tx.output[0].clone(), exit);

        let result = fixture.verify_with(&fixture.txs(), &unrolled(&fixture, vtxo));

        assert_rejected(result, "has no exit path");
    }

    #[test]
    fn rejects_a_published_transaction_whose_outputs_were_not_read() {
        let fixture = Fixture::new();
        let mut l1_outputs = fixture.l1_outputs();
        l1_outputs.get_mut(&fixture.commitment).unwrap().spent_by = Some(fixture.tree_txid());

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "is needed");
    }

    #[test]
    fn rejects_an_escrow_vtxo_already_spent_on_bitcoin() {
        let fixture = Fixture::new();
        let escrow = OutPoint::new(fixture.ark_txid(), 0);
        let vtxo = spent(
            fixture.tree.unsigned_tx.output[0].clone(),
            fixture.ark_txid(),
        );
        let mut l1_outputs = unrolled(&fixture, vtxo);
        l1_outputs.insert(
            escrow,
            spent(
                fixture.ark.unsigned_tx.output[0].clone(),
                Txid::from_byte_array([9; 32]),
            ),
        );

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "was spent on Bitcoin by");
    }

    #[test]
    fn rejects_a_published_escrow_vtxo_nobody_looked_at() {
        let fixture = Fixture::new();
        let vtxo = spent(
            fixture.tree.unsigned_tx.output[0].clone(),
            fixture.ark_txid(),
        );

        let result = fixture.verify_with(&fixture.txs(), &unrolled(&fixture, vtxo));

        assert_rejected(result, "is needed");
    }
}
