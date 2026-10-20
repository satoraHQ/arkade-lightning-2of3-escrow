use anyhow::{Context, Result};
use ark_core::send::{self, OffchainTransactions, SendReceiver, VtxoInput};
use ark_core::server;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Amount, OutPoint, Psbt, XOnlyPublicKey};

use crate::contract::{EscrowContract, SignerSet};
use crate::{FeeOutput, ReleaseMode, plan_release};

/// Everything needed to describe an escrow VTXO that will be spent.
pub struct EscrowVtxo {
    /// The outpoint of the escrow VTXO on the virtual tx graph.
    pub outpoint: OutPoint,
    /// The amount locked in the escrow.
    pub amount: Amount,
}

/// The result of building an escrow spend transaction.
///
/// Contains the ark_tx PSBT (needs signer + server sigs) and the checkpoint
/// PSBTs that will be signed after server co-signs.
pub struct EscrowTransaction {
    pub ark_tx: Psbt,
    pub checkpoint_txs: Vec<Psbt>,
}

/// Build the offchain release transaction.
///
/// Produces an ark_tx spending the escrow VTXO.
/// Outputs go to:
///   - Buyer's destination address (escrow amount minus fee)
///   - Arbiter's fee address (if fee > 0)
///
/// The returned PSBTs are unsigned — callers collect signatures from
/// signing parties before submitting.
pub fn build_release_tx(
    contract: &EscrowContract,
    escrow_vtxo: &EscrowVtxo,
    buyer_dest: &ark_core::ArkAddress,
    fee_outputs: &[FeeOutput],
    signer_set: SignerSet,
    server_info: &server::Info,
) -> Result<EscrowTransaction> {
    let spend_script = signer_set.script(contract.options());
    let control_block = contract.control_block(&spend_script)?;

    let vtxo_input = VtxoInput::new(
        spend_script,
        None, // no CLTV locktime
        control_block,
        contract.tapscripts(),
        contract.script_pubkey(),
        escrow_vtxo.amount,
        escrow_vtxo.outpoint,
        Vec::new(),
    );

    let release_plan = plan_release(
        escrow_vtxo.amount,
        fee_outputs,
        ReleaseMode::Offchain,
        server_info.dust,
    )?;

    let mut receivers = Vec::new();
    receivers.push(SendReceiver::bitcoin(
        *buyer_dest,
        release_plan.buyer_amount,
    ));

    for fee_output in &release_plan.effective_fee_outputs {
        receivers.push(SendReceiver::bitcoin(fee_output.address, fee_output.amount));
    }

    let OffchainTransactions {
        ark_tx,
        checkpoint_txs,
    } = send::build_offchain_transactions(
        &receivers,
        buyer_dest, // no change expected — full spend
        std::slice::from_ref(&vtxo_input),
        server_info,
    )
    .context("building release offchain transactions")?;

    Ok(EscrowTransaction {
        ark_tx,
        checkpoint_txs,
    })
}

/// Build the offchain refund transaction.
///
/// Returns the full escrow amount to the seller destination (no fee output).
pub fn build_refund_tx(
    contract: &EscrowContract,
    escrow_vtxo: &EscrowVtxo,
    seller_dest: &ark_core::ArkAddress,
    signer_set: SignerSet,
    server_info: &server::Info,
) -> Result<EscrowTransaction> {
    let spend_script = signer_set.script(contract.options());
    let control_block = contract.control_block(&spend_script)?;

    let vtxo_input = VtxoInput::new(
        spend_script,
        None,
        control_block,
        contract.tapscripts(),
        contract.script_pubkey(),
        escrow_vtxo.amount,
        escrow_vtxo.outpoint,
        Vec::new(),
    );

    let receivers = [SendReceiver::bitcoin(*seller_dest, escrow_vtxo.amount)];

    let OffchainTransactions {
        ark_tx,
        checkpoint_txs,
    } = send::build_offchain_transactions(
        &receivers,
        seller_dest,
        std::slice::from_ref(&vtxo_input),
        server_info,
    )
    .context("building refund offchain transactions")?;

    Ok(EscrowTransaction {
        ark_tx,
        checkpoint_txs,
    })
}

// --- Signing helpers ---

/// Sign the ark_tx PSBT with a single escrow signer keypair.
///
/// Adds a tapscript signature for the given key on input 0 (the escrow VTXO).
pub fn sign_ark_tx(psbt: &mut Psbt, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    send::sign_ark_transaction(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        psbt,
        0, // escrow VTXO is always input 0
    )
    .context("signing ark transaction")?;

    Ok(())
}

/// Sign a checkpoint PSBT with a single keypair.
pub fn sign_checkpoint(psbt: &mut Psbt, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    send::sign_checkpoint_transaction(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        psbt,
    )
    .context("signing checkpoint transaction")?;

    Ok(())
}

// --- Server co-signature verification ---

/// Compute the taproot script-spend sighash for `input_index` of `psbt`,
/// using the leaf recorded in the input's `tap_scripts`.
///
/// Mirrors what [`ark_core::send::sign_ark_transaction`] signs.
pub fn ark_tx_sighash(
    psbt: &Psbt,
    input_index: usize,
) -> Result<(secp256k1::Message, TapLeafHash)> {
    let witness_utxos = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .with_context(|| format!("input {i} has no witness_utxo"))
        })
        .collect::<Result<Vec<_>>>()?;
    let input = psbt
        .inputs
        .get(input_index)
        .with_context(|| format!("no input at index {input_index}"))?;
    let (_, (leaf_script, leaf_version)) = input
        .tap_scripts
        .first_key_value()
        .context("input has no tap_scripts entry")?;
    let leaf_hash = TapLeafHash::from_script(leaf_script, *leaf_version);
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&witness_utxos),
            leaf_hash,
            TapSighashType::Default,
        )
        .context("computing ark tx sighash")?;
    Ok((
        secp256k1::Message::from_digest(sighash.to_raw_hash().to_byte_array()),
        leaf_hash,
    ))
}

/// Check that `server_signed` is the server's co-signed copy of `local` and
/// return the canonical co-signed PSBT: `local` plus the verified server
/// signature.
///
/// The server key is taken from the escrow leaf recorded in `local`'s
/// `tap_scripts` (the last `CHECKSIG` key of the collaborative 3-of-3
/// script), not from anything the server announces: only a signature by
/// that key makes the leaf spendable. The signature must be a `Default`
/// sighash Schnorr signature over input 0 of the same unsigned transaction.
///
/// This is the client-side half of the protocol invariant: party checkpoint
/// signatures are only released (via `finalize`) once the server has
/// committed to the ark transaction that pays the parties out. Only the
/// verified signature is taken from the server's response; everything else
/// (party signatures, control blocks, witness data) comes from `local`.
pub fn verify_server_ark_tx_sig(local: &Psbt, server_signed: &Psbt) -> Result<Psbt> {
    anyhow::ensure!(
        server_signed.unsigned_tx == local.unsigned_tx,
        "server returned a different ark transaction (local {}, server {})",
        local.unsigned_tx.compute_txid(),
        server_signed.unsigned_tx.compute_txid(),
    );
    let server_key = escrow_leaf_server_key(local, 0)?;
    let (msg, leaf_hash) = ark_tx_sighash(local, 0)?;
    let input = server_signed
        .inputs
        .first()
        .context("server ark tx has no inputs")?;
    let sig = input
        .tap_script_sigs
        .get(&(server_key, leaf_hash))
        .with_context(|| {
            format!(
                "server did not co-sign the ark transaction with the leaf's server key {server_key}"
            )
        })?;
    anyhow::ensure!(
        sig.sighash_type == TapSighashType::Default,
        "server signature uses sighash type {:?}, expected Default",
        sig.sighash_type
    );
    Secp256k1::verification_only()
        .verify_schnorr(&sig.signature, &msg, &server_key)
        .with_context(|| format!("server signature by {server_key} is invalid"))?;

    let mut canonical = local.clone();
    canonical.inputs[0]
        .tap_script_sigs
        .insert((server_key, leaf_hash), *sig);
    Ok(canonical)
}

/// The server key of the collaborative escrow leaf recorded for `input_index`.
fn escrow_leaf_server_key(psbt: &Psbt, input_index: usize) -> Result<XOnlyPublicKey> {
    let input = psbt
        .inputs
        .get(input_index)
        .with_context(|| format!("no input at index {input_index}"))?;
    let (_, (leaf_script, _)) = input
        .tap_scripts
        .first_key_value()
        .context("input has no tap_scripts entry")?;
    let keys = ark_core::script::extract_checksig_pubkeys(leaf_script);
    anyhow::ensure!(
        keys.len() == 3,
        "escrow leaf has {} CHECKSIG keys, expected 3 (party, party, server)",
        keys.len()
    );
    Ok(keys[2])
}

// --- Signature merging ---

/// Merge tap_script_sigs from one PSBT into another.
///
/// Takes the base PSBT (with one party's sigs) and merges sigs from another
/// copy. Both PSBTs must have the same unsigned tx.
pub fn merge_ark_tx_sigs(base: &mut Psbt, other: &Psbt) -> Result<()> {
    anyhow::ensure!(
        base.unsigned_tx == other.unsigned_tx,
        "refusing to merge signatures: unsigned transactions differ",
    );
    anyhow::ensure!(
        base.inputs.len() == other.inputs.len(),
        "refusing to merge signatures: input counts differ (base {}, other {})",
        base.inputs.len(),
        other.inputs.len(),
    );

    for (base_input, other_input) in base.inputs.iter_mut().zip(&other.inputs) {
        for (key, sig) in &other_input.tap_script_sigs {
            base_input
                .tap_script_sigs
                .entry(*key)
                .or_insert_with(|| *sig);
        }
    }
    Ok(())
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::contract::EscrowOptions;
    use bitcoin::key::Parity;
    use bitcoin::secp256k1::rand;
    use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootMerkleBranch};
    use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction};

    struct Fixture {
        local: Psbt,
        server: Keypair,
        other: Keypair,
    }

    fn fixture() -> Fixture {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let [seller, buyer, arbiter, server, other] =
            std::array::from_fn(|_| Keypair::new(&secp, &mut rng));
        let options = EscrowOptions {
            seller: seller.x_only_public_key().0,
            buyer: buyer.x_only_public_key().0,
            arbiter: arbiter.x_only_public_key().0,
            server: server.x_only_public_key().0,
            unilateral_exit_delay: Sequence::from_height(10),
        };
        let mut local = Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        })
        .unwrap();
        local.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: ScriptBuf::new(),
        });
        local.inputs[0].tap_scripts.insert(
            ControlBlock {
                leaf_version: LeafVersion::TapScript,
                output_key_parity: Parity::Even,
                internal_key: server.x_only_public_key().0,
                merkle_branch: TaprootMerkleBranch::default(),
            },
            (options.buyer_arbiter_script(), LeafVersion::TapScript),
        );
        sign_ark_tx(&mut local, &buyer).unwrap();
        sign_ark_tx(&mut local, &arbiter).unwrap();
        Fixture {
            local,
            server,
            other,
        }
    }

    #[test]
    fn accepts_a_valid_server_signature_and_returns_the_canonical_psbt() {
        let f = fixture();
        let mut response = f.local.clone();
        // The server strips party data and adds its own signature.
        response.inputs[0].tap_script_sigs.clear();
        response.inputs[0].tap_scripts.clear();
        response.inputs[0].witness_utxo = None;
        let mut signed = f.local.clone();
        sign_ark_tx(&mut signed, &f.server).unwrap();
        let (_, leaf_hash) = ark_tx_sighash(&f.local, 0).unwrap();
        let server_key = f.server.x_only_public_key().0;
        let sig = signed.inputs[0].tap_script_sigs[&(server_key, leaf_hash)];
        response.inputs[0]
            .tap_script_sigs
            .insert((server_key, leaf_hash), sig);

        let canonical = verify_server_ark_tx_sig(&f.local, &response).unwrap();
        assert_eq!(canonical.inputs[0].tap_script_sigs.len(), 3);
        assert!(canonical.inputs[0].witness_utxo.is_some());
        assert_eq!(canonical.inputs[0].tap_scripts.len(), 1);
    }

    #[test]
    fn rejects_a_signature_by_a_key_that_is_not_the_leaf_server_key() {
        let f = fixture();
        let mut response = f.local.clone();
        sign_ark_tx(&mut response, &f.other).unwrap();
        let err = verify_server_ark_tx_sig(&f.local, &response).unwrap_err();
        assert!(format!("{err:#}").contains("did not co-sign"), "{err:#}");
    }

    #[test]
    fn rejects_a_missing_signature_even_with_party_signatures_present() {
        let f = fixture();
        let err = verify_server_ark_tx_sig(&f.local, &f.local).unwrap_err();
        assert!(format!("{err:#}").contains("did not co-sign"), "{err:#}");
    }

    #[test]
    fn rejects_a_server_signature_over_a_different_transaction() {
        let f = fixture();
        let mut other_tx = f.local.clone();
        other_tx.unsigned_tx.output[0].value = Amount::from_sat(999);
        sign_ark_tx(&mut other_tx, &f.server).unwrap();
        let (_, leaf_hash) = ark_tx_sighash(&f.local, 0).unwrap();
        let server_key = f.server.x_only_public_key().0;
        let sig = other_tx.inputs[0].tap_script_sigs[&(server_key, leaf_hash)];
        // Transplant the signature onto a response for the right tx.
        let mut response = f.local.clone();
        response.inputs[0]
            .tap_script_sigs
            .insert((server_key, leaf_hash), sig);
        let err = verify_server_ark_tx_sig(&f.local, &response).unwrap_err();
        assert!(format!("{err:#}").contains("invalid"), "{err:#}");

        // And a response whose unsigned tx differs is rejected before any check.
        let err = verify_server_ark_tx_sig(&f.local, &other_tx).unwrap_err();
        assert!(
            format!("{err:#}").contains("different ark transaction"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_a_non_default_sighash_type() {
        let f = fixture();
        let mut response = f.local.clone();
        sign_ark_tx(&mut response, &f.server).unwrap();
        let (_, leaf_hash) = ark_tx_sighash(&f.local, 0).unwrap();
        let server_key = f.server.x_only_public_key().0;
        let sig = response.inputs[0]
            .tap_script_sigs
            .get_mut(&(server_key, leaf_hash))
            .unwrap();
        sig.sighash_type = TapSighashType::All;
        let err = verify_server_ark_tx_sig(&f.local, &response).unwrap_err();
        assert!(format!("{err:#}").contains("sighash type"), "{err:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute;
    use bitcoin::blockdata::transaction::Version;
    use bitcoin::sighash::TapSighashType;
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, taproot};

    fn psbt_with_inputs(input_count: usize) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                };
                input_count
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn add_tap_script_sig(psbt: &mut Psbt, input_index: usize) {
        let pk: XOnlyPublicKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap();
        let leaf_hash =
            TapLeafHash::from_script(ScriptBuf::new().as_script(), LeafVersion::TapScript);
        let sig = taproot::Signature {
            signature: schnorr::Signature::from_slice(&[4; 64]).unwrap(),
            sighash_type: TapSighashType::Default,
        };
        psbt.inputs[input_index]
            .tap_script_sigs
            .insert((pk, leaf_hash), sig);
    }

    #[test]
    fn merge_rejects_different_unsigned_transactions() {
        let mut base = psbt_with_inputs(1);
        let mut other = psbt_with_inputs(2);
        add_tap_script_sig(&mut other, 1);

        let err = merge_ark_tx_sigs(&mut base, &other)
            .unwrap_err()
            .to_string();

        assert!(err.contains("unsigned transactions differ"));
    }

    #[test]
    fn merge_copies_tap_script_sigs_for_same_transaction() {
        let mut base = psbt_with_inputs(1);
        let mut other = base.clone();
        add_tap_script_sig(&mut other, 0);

        merge_ark_tx_sigs(&mut base, &other).unwrap();

        assert_eq!(
            base.inputs[0].tap_script_sigs,
            other.inputs[0].tap_script_sigs
        );
    }
}
