use anyhow::{Result, anyhow, bail};
use ark_core::{ArkAddress, UNSPENDABLE_KEY};
use bitcoin::opcodes::all::*;
use bitcoin::taproot::{ControlBlock, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Network, PublicKey, ScriptBuf, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Configuration for a 2-of-3 escrow contract on Arkade.
///
/// Any two of {seller, buyer, arbiter} can spend. Collaborative paths include the
/// Arkade server signature; unilateral paths use CSV delay instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowOptions {
    /// Seller's public key (the party funding the escrow).
    #[serde(alias = "alice")]
    pub seller: XOnlyPublicKey,
    /// Buyer's public key.
    #[serde(alias = "bob")]
    pub buyer: XOnlyPublicKey,
    /// Arbiter's public key.
    pub arbiter: XOnlyPublicKey,
    /// Arkade server's public key.
    pub server: XOnlyPublicKey,
    /// CSV delay for unilateral exit paths (no server needed).
    pub unilateral_exit_delay: bitcoin::Sequence,
}

/// Collaborative signer set used to spend an escrow VTXO with the Arkade server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerSet {
    BuyerArbiter,
    SellerArbiter,
    SellerBuyer,
}

impl SignerSet {
    pub fn script(self, options: &EscrowOptions) -> ScriptBuf {
        match self {
            SignerSet::BuyerArbiter => options.buyer_arbiter_script(),
            SignerSet::SellerArbiter => options.seller_arbiter_script(),
            SignerSet::SellerBuyer => options.seller_buyer_script(),
        }
    }
}

impl EscrowOptions {
    /// Validate that all keys are distinct and the delay is non-zero.
    pub fn validate(&self) -> Result<()> {
        let keys = [self.seller, self.buyer, self.arbiter, self.server];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                if keys[i] == keys[j] {
                    bail!("all public keys must be distinct");
                }
            }
        }

        let delay = self.unilateral_exit_delay.to_consensus_u32();
        if delay == 0 {
            bail!("unilateral_exit_delay must be non-zero");
        }
        if !self.unilateral_exit_delay.is_relative_lock_time() {
            bail!("unilateral_exit_delay must be a BIP68 relative lock-time");
        }

        Ok(())
    }

    // -- Collaborative leaves (include server_pk) --

    /// Leaf 1: seller + arbiter + server.
    pub fn seller_arbiter_script(&self) -> ScriptBuf {
        collaborative_3of3(self.seller, self.arbiter, self.server)
    }

    /// Leaf 2: buyer + arbiter + server.
    pub fn buyer_arbiter_script(&self) -> ScriptBuf {
        collaborative_3of3(self.buyer, self.arbiter, self.server)
    }

    /// Leaf 3: seller + buyer + server — mutual settlement, no arbiter needed.
    pub fn seller_buyer_script(&self) -> ScriptBuf {
        collaborative_3of3(self.seller, self.buyer, self.server)
    }

    // -- Unilateral leaves (CSV delay, no server) --

    /// Leaf 4: CSV + seller + arbiter.
    pub fn unilateral_seller_arbiter_script(&self) -> ScriptBuf {
        unilateral_2of2(self.unilateral_exit_delay, self.seller, self.arbiter)
    }

    /// Leaf 5: CSV + buyer + arbiter.
    pub fn unilateral_buyer_arbiter_script(&self) -> ScriptBuf {
        unilateral_2of2(self.unilateral_exit_delay, self.buyer, self.arbiter)
    }

    /// Leaf 6: CSV + seller + buyer — unilateral mutual settlement.
    pub fn unilateral_seller_buyer_script(&self) -> ScriptBuf {
        unilateral_2of2(self.unilateral_exit_delay, self.seller, self.buyer)
    }
}

/// The escrow contract: wraps options + computed taproot spend info.
#[derive(Clone)]
pub struct EscrowContract {
    options: EscrowOptions,
    spend_info: TaprootSpendInfo,
    network: Network,
}

impl EscrowContract {
    pub fn new(options: EscrowOptions, network: Network) -> Result<Self> {
        options.validate()?;
        let spend_info = build_taproot(&options)?;
        Ok(Self {
            options,
            spend_info,
            network,
        })
    }

    pub fn options(&self) -> &EscrowOptions {
        &self.options
    }

    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.spend_info
    }

    pub(crate) fn with_server(&self, server: XOnlyPublicKey) -> Result<Self> {
        let mut options = self.options.clone();
        options.server = server;
        Self::new(options, self.network)
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::builder()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(self.spend_info.output_key().serialize())
            .into_script()
    }

    pub fn address(&self) -> ArkAddress {
        ArkAddress::new(
            self.network,
            self.options.server,
            self.spend_info.output_key(),
        )
    }

    /// All 6 tapscripts in tree order (collaborative then unilateral).
    pub fn tapscripts(&self) -> Vec<ScriptBuf> {
        vec![
            self.options.seller_arbiter_script(),
            self.options.buyer_arbiter_script(),
            self.options.seller_buyer_script(),
            self.options.unilateral_seller_arbiter_script(),
            self.options.unilateral_buyer_arbiter_script(),
            self.options.unilateral_seller_buyer_script(),
        ]
    }

    /// Get the control block for spending via a specific leaf script.
    pub fn control_block(&self, script: &ScriptBuf) -> Result<ControlBlock> {
        self.spend_info
            .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("script not found in taproot tree"))
    }
}

// -- Script builders --

fn collaborative_3of3(
    pk_a: XOnlyPublicKey,
    pk_b: XOnlyPublicKey,
    server: XOnlyPublicKey,
) -> ScriptBuf {
    ScriptBuf::builder()
        .push_x_only_key(&pk_a)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&pk_b)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&server)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn unilateral_2of2(
    delay: bitcoin::Sequence,
    pk_a: XOnlyPublicKey,
    pk_b: XOnlyPublicKey,
) -> ScriptBuf {
    ScriptBuf::builder()
        .push_int(delay.to_consensus_u32() as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&pk_a)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&pk_b)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

// -- Taproot tree construction --
// Ported from escrow-sample.rs: weight-based balanced tree for 6 leaves.

#[derive(Clone)]
enum TreeNode {
    Leaf {
        script: ScriptBuf,
        weight: u32,
    },
    Branch {
        left: Box<TreeNode>,
        right: Box<TreeNode>,
        weight: u32,
    },
}

impl TreeNode {
    fn weight(&self) -> u32 {
        match self {
            TreeNode::Leaf { weight, .. } | TreeNode::Branch { weight, .. } => *weight,
        }
    }
}

fn build_taproot(opts: &EscrowOptions) -> Result<TaprootSpendInfo> {
    let internal_key =
        XOnlyPublicKey::from(PublicKey::from_str(UNSPENDABLE_KEY).expect("valid unspendable key"));

    // All leaves equal weight (balanced tree).
    let scripts = vec![
        opts.seller_arbiter_script(),
        opts.buyer_arbiter_script(),
        opts.seller_buyer_script(),
        opts.unilateral_seller_arbiter_script(),
        opts.unilateral_buyer_arbiter_script(),
        opts.unilateral_seller_buyer_script(),
    ];

    let mut nodes: Vec<TreeNode> = scripts
        .into_iter()
        .map(|s| TreeNode::Leaf {
            script: s,
            weight: 1,
        })
        .collect();

    // Build tree by repeatedly combining the two lightest nodes.
    while nodes.len() >= 2 {
        nodes.sort_by_key(|n| std::cmp::Reverse(n.weight()));
        let b = nodes.pop().unwrap();
        let a = nodes.pop().unwrap();
        nodes.push(TreeNode::Branch {
            weight: a.weight() + b.weight(),
            left: Box::new(a),
            right: Box::new(b),
        });
    }

    let root = nodes.into_iter().next().unwrap();
    let builder = add_to_builder(TaprootBuilder::new(), &root, 0)?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    builder
        .finalize(&secp, internal_key)
        .map_err(|_| anyhow!("failed to finalize taproot tree"))
}

fn add_to_builder(builder: TaprootBuilder, node: &TreeNode, depth: u8) -> Result<TaprootBuilder> {
    match node {
        TreeNode::Leaf { script, .. } => builder
            .add_leaf(depth, script.clone())
            .map_err(|_| anyhow!("failed to add leaf at depth {depth}")),
        TreeNode::Branch { left, right, .. } => {
            let builder = add_to_builder(builder, left, depth + 1)?;
            add_to_builder(builder, right, depth + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::Secp256k1;

    fn test_options() -> EscrowOptions {
        let secp = Secp256k1::new();
        let mut rng = bitcoin::secp256k1::rand::thread_rng();
        let seller = Keypair::new(&secp, &mut rng).x_only_public_key().0;
        let buyer = Keypair::new(&secp, &mut rng).x_only_public_key().0;
        let arbiter = Keypair::new(&secp, &mut rng).x_only_public_key().0;
        let server = Keypair::new(&secp, &mut rng).x_only_public_key().0;

        EscrowOptions {
            seller,
            buyer,
            arbiter,
            server,
            unilateral_exit_delay: bitcoin::Sequence(512),
        }
    }

    #[test]
    fn contract_address_is_deterministic() {
        let opts = test_options();
        let c1 = EscrowContract::new(opts.clone(), Network::Regtest).unwrap();
        let c2 = EscrowContract::new(opts, Network::Regtest).unwrap();
        assert_eq!(c1.address().to_string(), c2.address().to_string());
    }

    #[test]
    fn contract_has_six_tapscripts() {
        let opts = test_options();
        let contract = EscrowContract::new(opts, Network::Regtest).unwrap();
        assert_eq!(contract.tapscripts().len(), 6);
    }

    #[test]
    fn control_blocks_exist_for_all_leaves() {
        let opts = test_options();
        let contract = EscrowContract::new(opts, Network::Regtest).unwrap();
        for script in &contract.tapscripts() {
            contract.control_block(script).unwrap();
        }
    }

    #[test]
    fn validate_rejects_duplicate_keys() {
        let secp = Secp256k1::new();
        let mut rng = bitcoin::secp256k1::rand::thread_rng();
        let k = Keypair::new(&secp, &mut rng).x_only_public_key().0;
        let other = Keypair::new(&secp, &mut rng).x_only_public_key().0;

        let opts = EscrowOptions {
            seller: k,
            buyer: k,
            arbiter: other,
            server: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            unilateral_exit_delay: bitcoin::Sequence(512),
        };
        assert!(opts.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_delay() {
        let secp = Secp256k1::new();
        let mut rng = bitcoin::secp256k1::rand::thread_rng();

        let opts = EscrowOptions {
            seller: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            buyer: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            arbiter: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            server: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            unilateral_exit_delay: bitcoin::Sequence(0),
        };
        assert!(opts.validate().is_err());
    }

    #[test]
    fn validate_rejects_disabled_relative_locktime() {
        let secp = Secp256k1::new();
        let mut rng = bitcoin::secp256k1::rand::thread_rng();

        // 0xFFFFFFFF has the BIP68 disable flag set, so it is not a relative
        // lock-time even though it is non-zero.
        let opts = EscrowOptions {
            seller: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            buyer: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            arbiter: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            server: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            unilateral_exit_delay: bitcoin::Sequence(0xFFFFFFFF),
        };
        assert!(opts.validate().is_err());
    }

    fn random_options_with_delay(delay: bitcoin::Sequence) -> EscrowOptions {
        let secp = Secp256k1::new();
        let mut rng = bitcoin::secp256k1::rand::thread_rng();
        EscrowOptions {
            seller: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            buyer: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            arbiter: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            server: Keypair::new(&secp, &mut rng).x_only_public_key().0,
            unilateral_exit_delay: delay,
        }
    }

    #[test]
    fn consensus_sequence_roundtrips_for_seconds_delay() {
        // The Ark server advertises a seconds-based delay encoded as a BIP68
        // consensus u32. Feeding that raw u32 into `bitcoin::Sequence` must
        // produce the same escrow address as the original `Sequence`.
        let opts = random_options_with_delay(bitcoin::Sequence::from_seconds_ceil(512).unwrap());
        let consensus = opts.unilateral_exit_delay.to_consensus_u32();

        let expected = EscrowContract::new(opts.clone(), Network::Regtest)
            .unwrap()
            .address()
            .to_string();
        let mut from_server = opts;
        from_server.unilateral_exit_delay = bitcoin::Sequence(consensus);
        let from_server = EscrowContract::new(from_server, Network::Regtest)
            .unwrap()
            .address()
            .to_string();

        assert_eq!(from_server, expected);
    }

    #[test]
    fn consensus_sequence_roundtrips_for_block_delay() {
        // Same check for a block-based delay.
        let opts = random_options_with_delay(bitcoin::Sequence::from_height(1000));
        let consensus = opts.unilateral_exit_delay.to_consensus_u32();

        let expected = EscrowContract::new(opts.clone(), Network::Regtest)
            .unwrap()
            .address()
            .to_string();
        let mut from_server = opts;
        from_server.unilateral_exit_delay = bitcoin::Sequence(consensus);
        let from_server = EscrowContract::new(from_server, Network::Regtest)
            .unwrap()
            .address()
            .to_string();

        assert_eq!(from_server, expected);
    }

    #[test]
    fn reinterpreting_consensus_seconds_as_raw_seconds_changes_address() {
        // This is the bug that used to live in the Ruby FFI layer: the raw
        // consensus u32 for a 512-second delay (0x00400001) was passed to
        // `Sequence::from_seconds_ceil` again, treating the flagged value as a
        // plain second count. The resulting address must differ from the
        // correct one.
        let correct_opts =
            random_options_with_delay(bitcoin::Sequence::from_seconds_ceil(512).unwrap());
        let consensus = correct_opts.unilateral_exit_delay.to_consensus_u32();

        let correct = EscrowContract::new(correct_opts.clone(), Network::Regtest)
            .unwrap()
            .address()
            .to_string();

        let mut wrong_opts = correct_opts;
        wrong_opts.unilateral_exit_delay = bitcoin::Sequence::from_seconds_ceil(consensus).unwrap();
        let wrong = EscrowContract::new(wrong_opts, Network::Regtest)
            .unwrap()
            .address()
            .to_string();

        assert_ne!(correct, wrong);
    }
}
