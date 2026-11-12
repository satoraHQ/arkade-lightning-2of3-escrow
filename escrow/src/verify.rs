//! Proof that a VTXO the Arkade indexer reports is backed by Bitcoin.
//!
//! The indexer is the operator's own account of who owns what, so its word that an escrow is
//! funded is only as good as the operator (HH-ARK-111). What does not depend on it is the
//! unilateral-exit path: the presigned virtual transactions that lead from a batch output in a
//! commitment transaction down to the VTXO. Every transaction on that path is a real Bitcoin
//! transaction the owner could publish, so if each one is signed, spends its parent and ends in
//! an output paying the escrow, the VTXO is as real as the commitment output it starts from.
//!
//! The commitment outputs themselves come from the caller, read from Bitcoin rather than from the
//! indexer. The caller still has to decide how many confirmations those commitment transactions
//! need; this module only says which ones the VTXO stands on.

use std::collections::HashMap;

use anyhow::{Context, Result, bail, ensure};
use ark_core::server::VtxoChains;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, Verification};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, TxOut, Txid, XOnlyPublicKey};

/// More virtual transactions than any escrow deposit path has; bounds what the indexer can make
/// us walk.
pub const MAX_CHAIN_LEN: usize = 1_000;

/// Check that the VTXO at `outpoint`, paying `amount` to `script`, descends from Bitcoin outputs.
///
/// `chains` and `virtual_txs` are the indexer's `GetVtxoChain` and `GetVirtualTxs` answers for the
/// VTXO. `l1_outputs` are outputs of the commitment transactions as Bitcoin knows them.
/// `operator_keys` are the Arkade signer keys, current and deprecated: every VTXO spend on the
/// path must be cosigned by one of them, as an offchain spend always is. Without that, the owner
/// of a real VTXO could present a spend of it through the exit leaf alone and keep the VTXO.
///
/// Returns the commitment transactions the VTXO's path starts from, so the caller can require
/// confirmations on exactly those.
pub fn verify_vtxo_chain(
    outpoint: OutPoint,
    script: &ScriptBuf,
    amount: Amount,
    chains: &VtxoChains,
    virtual_txs: &[Psbt],
    l1_outputs: &HashMap<OutPoint, TxOut>,
    operator_keys: &[XOnlyPublicKey],
) -> Result<Vec<Txid>> {
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
        "VTXO output {outpoint} is worth {}, not the reported {amount}",
        leaf_output.value
    );

    let secp = Secp256k1::verification_only();
    let mut anchors = Vec::new();

    for txid in &branch {
        let psbt = branch_txs[txid];
        let mut prevouts = Vec::with_capacity(psbt.unsigned_tx.input.len());

        for input in &psbt.unsigned_tx.input {
            let spent = input.previous_output;
            let prevout = match branch_txs.get(&spent.txid) {
                Some(parent) => parent.unsigned_tx.output.get(spent.vout as usize).cloned(),
                None => {
                    anchors.push(spent.txid);
                    l1_outputs.get(&spent).cloned()
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
    }

    anchors.sort();
    anchors.dedup();

    Ok(anchors)
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
    // operator.
    // ponytail: checks the leaf is committed to, names the operator, and every CHECKSIG key in it
    // signed; timelocks and hash conditions in the leaf are not evaluated. A script interpreter
    // would close that.
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

        return Ok(());
    }

    bail!("no tapleaf of the spent output is signed by its keys and the operator")
}

fn taproot_output_key(script: &ScriptBuf) -> Result<XOnlyPublicKey> {
    ensure!(script.is_p2tr(), "spent output {script} is not taproot");
    Ok(XOnlyPublicKey::from_slice(&script.as_bytes()[2..34])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_core::server::{ChainedTxType, VtxoChain};
    use bitcoin::absolute::LockTime;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::All;
    use bitcoin::sighash::TapSighashType;
    use bitcoin::taproot::{self, LeafVersion, TaprootBuilder, TaprootSpendInfo};
    use bitcoin::transaction::Version;
    use bitcoin::{Transaction, TxIn};

    const VALUE: Amount = Amount::from_sat(10_000);

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
    }

    impl Fixture {
        fn new() -> Self {
            let secp = Secp256k1::new();
            let [cosigner, owner, operator, escrow] =
                std::array::from_fn(|_| Keypair::new(&secp, &mut rand::thread_rng()));

            let commitment = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
            let batch_output = TxOut {
                value: VALUE,
                script_pubkey: ScriptBuf::new_p2tr(&secp, cosigner.x_only_public_key().0, None),
            };
            let escrow_script = ScriptBuf::new_p2tr(&secp, escrow.x_only_public_key().0, None);

            let (_, vtxo_info) = vtxo_leaf(&secp, &owner, &operator);
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
            let (script, info) = vtxo_leaf(&self.secp, &self.owner, &self.operator);
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

        fn l1_outputs(&self) -> HashMap<OutPoint, TxOut> {
            HashMap::from([(self.commitment, self.batch_output.clone())])
        }

        fn txs(&self) -> Vec<Psbt> {
            vec![self.tree.clone(), self.ark.clone()]
        }

        fn operator_keys(&self) -> Vec<XOnlyPublicKey> {
            vec![self.operator.x_only_public_key().0]
        }

        fn verify(&self) -> Result<Vec<Txid>> {
            self.verify_with(&self.txs(), &self.l1_outputs())
        }

        fn verify_with(
            &self,
            txs: &[Psbt],
            l1_outputs: &HashMap<OutPoint, TxOut>,
        ) -> Result<Vec<Txid>> {
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
            l1_outputs: &HashMap<OutPoint, TxOut>,
            operator_keys: &[XOnlyPublicKey],
        ) -> Result<Vec<Txid>> {
            verify_vtxo_chain(
                OutPoint::new(self.ark_txid(), 0),
                script,
                amount,
                &self.chains(),
                txs,
                l1_outputs,
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
        let info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(secp, owner.x_only_public_key().0)
            .unwrap();
        (script, info)
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

    fn assert_rejected(result: Result<Vec<Txid>>, reason: &str) {
        let error = format!("{:#}", result.expect_err("chain should be rejected"));
        assert!(error.contains(reason), "{error}");
    }

    fn stranger(fixture: &Fixture) -> Keypair {
        Keypair::new(&fixture.secp, &mut rand::thread_rng())
    }

    #[test]
    fn accepts_a_signed_path_from_a_bitcoin_output() {
        let fixture = Fixture::new();

        assert_eq!(fixture.verify().unwrap(), vec![fixture.commitment.txid]);
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

        assert_rejected(result, "not the reported");
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
            TxOut {
                value: VALUE,
                script_pubkey: fixture.escrow_script.clone(),
            },
        );

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "key-path signature does not verify");
    }

    #[test]
    fn rejects_value_the_bitcoin_output_does_not_hold() {
        let fixture = Fixture::new();
        let mut l1_outputs = fixture.l1_outputs();
        l1_outputs.get_mut(&fixture.commitment).unwrap().value = VALUE / 2;

        let result = fixture.verify_with(&fixture.txs(), &l1_outputs);

        assert_rejected(result, "spends only");
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
            &fixture.l1_outputs(),
            &fixture.operator_keys(),
        );

        assert_rejected(result, "more than");
    }
}
