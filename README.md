# ark-escrow

2-of-3 Bitcoin escrow contracts on [Arkade](https://arkade.co) (Ark protocol).

This SDK provides primitives for building escrow applications where any two of three parties (e.g. buyer, seller, arbiter) can collaboratively spend funds, with unilateral exit paths via CSV timelock.

## Architecture

### Taproot contract (6 leaves)

**Collaborative paths** (include Arkade server signature):
- Alice + Arbiter + Server — arbiter-assisted refund
- Bob + Arbiter + Server — arbiter-assisted release (happy path)
- Alice + Bob + Server — mutual settlement

**Unilateral paths** (CSV delay, no server needed):
- CSV + Alice + Arbiter — unilateral refund
- CSV + Bob + Arbiter — unilateral release
- CSV + Alice + Bob — unilateral mutual settlement

## Rust crate (`ark-escrow`)

```toml
[dependencies]
ark-escrow = { git = "https://github.com/lendasat/ark-escrow" }
```

### Core types

- **`EscrowContract`** — builds the taproot tree from 4 public keys + CSV delay
- **`EscrowClient`** — wraps Arkade gRPC (connect, find VTXOs, offchain spend with crash recovery, escrow refresh)
- **`build_release_tx`** / **`build_refund_tx`** — construct unsigned offchain release/refund PSBTs
- **`prepare_refresh`** — construct unsigned refresh PSBTs for recoverable VTXOs
- **`plan_release`** — compute effective payout and fee outputs without building PSBTs
- **`sign_ark_tx`** / **`sign_checkpoint`** / **`sign_refresh`** — Schnorr signing helpers
- **`merge_ark_tx_sigs`** — merge signatures from multiple parties
- **`SpendStore`** trait — pluggable crash-recovery storage for the two-phase offchain spend protocol

### Example

```rust
use ark_escrow::{
    FeeOutput,
    contract::{EscrowContract, EscrowOptions},
    client::EscrowClient,
    spend,
};

// 1. Create contract
let contract = EscrowContract::new(EscrowOptions {
    alice, bob, arbiter, server,
    unilateral_exit_delay: bitcoin::Sequence::from_height(144),
}, Network::Bitcoin)?;

// 2. Connect to Arkade and find the funded VTXO
let mut client = EscrowClient::new("https://arkade.computer:7070");
let info = client.connect().await?;
let vtxo = client.find_escrow_vtxo(&contract).await?
    .expect("escrow VTXO not found");

// 3. Build release transaction (with fee outputs)
let fee_outputs = vec![
    FeeOutput { address: fee_addr, amount: Amount::from_sat(100) },
];
let release = spend::build_release_tx(
    &contract, &vtxo, &bob_addr, &fee_outputs, info,
)?;

// 4. Sign (each party signs independently)
spend::sign_ark_tx(&mut release.ark_tx, &bob_keypair)?;
spend::sign_ark_tx(&mut arbiter_copy, &arbiter_keypair)?;
spend::merge_ark_tx_sigs(&mut release.ark_tx, &arbiter_copy)?;

// 5. Submit and finalize (with crash recovery via SpendStore)
let txid = client.spend_escrow_offchain(
    &store, "trade-id", release.ark_tx, release.checkpoint_txs, &party_cps,
).await?;
```

## Ruby FFI (`ark_escrow`)

Native extension providing the same primitives to Ruby.

### Build

```bash
cargo build --release -p ark-escrow-ruby
ln -sf target/release/libark_escrow_ruby.so target/release/ark_escrow_ruby.so      # Linux
ln -sf target/release/libark_escrow_ruby.dylib target/release/ark_escrow_ruby.bundle  # macOS
```

### Usage

```ruby
require 'ark_escrow'

# Connect to Arkade (with a custom crash-recovery store)
client = ArkEscrow::Client.with_custom_store("https://arkade.computer:7070", my_store)
client.connect

# Create contract
contract = ArkEscrow::Contract.new(
  alice_pk, bob_pk, arbiter_pk, client.server_pk,
  client.unilateral_exit_delay, "bitcoin"
)

# Find funded VTXO
outpoint, amount = client.find_escrow_vtxo(contract)

# Build release (with fee outputs as [address, sats] pairs)
fee_outputs = [["ark1...fee", 100]]
ark_tx_b64, checkpoint_b64s = client.build_release(
  contract, outpoint, amount, bob_dest_address, fee_outputs
)

# Sign and merge
signed = ArkEscrow.sign_ark_tx(ark_tx_b64, secret_key_hex)
merged = ArkEscrow.merge_sigs(signed, other_signed)

# Finalize with crash recovery
ark_txid = client.spend_escrow_offchain(
  trade_id, merged, unsigned_checkpoints, [arbiter_cps, bob_cps]
)
```

### Refreshing recoverable VTXOs

When escrow VTXOs become recoverable, first refresh them back into the same escrow contract address. The refreshed escrow then becomes spendable again and should be released/refunded using the normal offchain flow. This avoids direct settlement outputs for fees/referrals, which may be sub-dust.

```ruby
# Check VTXO status
pending, vtxos, any_recoverable = client.get_escrow_vtxo_status(trade_id, contract)

# Prepare + sign + refresh for release. Use "refund" for refund flows.
intent_b64, message_json, forfeit_b64s, cosigner_pk =
  client.prepare_refresh(contract, vtxos, "release", cosigner_sk)

signed_intent, signed_forfeits = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, bob_sk)
# ... merge arbiter + bob sigs, then:
txid = client.refresh_escrow(signed_intent, message_json, signed_forfeits, cosigner_sk)

# Once the refreshed VTXO is visible/spendable, use build_release/build_refund.
outpoint, amount = client.find_escrow_vtxo(contract)
```

Legacy direct delegated release methods remain for compatibility, but are deprecated.

### Rust logging

The Ruby extension initialises a `tracing` subscriber on load. Control verbosity via `RUST_LOG`:

```bash
RUST_LOG=ark_escrow=debug ruby my_app.rb
```

## Protocol

See [docs/protocol.md](docs/protocol.md) for the full PSBT exchange protocol.
