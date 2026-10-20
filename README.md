# ark-escrow

2-of-3 Bitcoin escrow contracts on [Arkade](https://arkade.co) (Ark protocol).

This SDK provides primitives for building escrow applications where any two of three parties (e.g. buyer, seller, arbiter) can collaboratively spend funds, with unilateral exit paths via CSV timelock.

## Architecture

### Taproot contract (6 leaves)

**Collaborative paths** (include Arkade server signature):
- Seller + Arbiter + Server
- Buyer + Arbiter + Server
- Seller + Buyer + Server — mutual settlement

**Unilateral paths** (CSV delay, no server needed):
- CSV + Seller + Arbiter
- CSV + Buyer + Arbiter
- CSV + Seller + Buyer — unilateral mutual settlement

## Rust crate (`ark-escrow`)

```toml
[dependencies]
ark-escrow = { git = "https://github.com/lendasat/ark-escrow" }
```

### Core types

- **`EscrowContract`** — builds the taproot tree from 4 public keys + CSV delay
- **`EscrowClient`** — wraps Arkade gRPC (connect, find VTXOs, offchain spend with crash recovery, escrow refresh)
- **`SignerSet`** — selects which collaborative leaf signs (`BuyerArbiter`, `SellerArbiter`, or `SellerBuyer`)
- **`build_release_tx`** / **`build_refund_tx`** — construct unsigned offchain PSBTs; callers choose the signer set
- **`prepare_refresh`** — construct unsigned refresh PSBTs for recoverable VTXOs
- **`plan_release`** — compute effective payout and fee outputs without building PSBTs
- **`sign_ark_tx`** / **`sign_checkpoint`** / **`sign_refresh`** — Schnorr signing helpers
- **`merge_ark_tx_sigs`** — merge signatures from multiple parties
- **`SpendStore`** trait — pluggable crash-recovery storage for the two-phase offchain spend protocol.
  A record is written *before* `submit` and removed only after `finalize`, guarded by a per-attempt token

### Example

```rust
use ark_escrow::{
    FeeOutput,
    contract::{EscrowContract, EscrowOptions, SignerSet},
    client::EscrowClient,
    spend,
};

// 1. Create contract
let contract = EscrowContract::new(EscrowOptions {
    seller, buyer, arbiter, server,
    unilateral_exit_delay: bitcoin::Sequence::from_height(144),
}, Network::Bitcoin)?;

// 2. Connect to Arkade and find the funded VTXO
let mut client = EscrowClient::new("https://arkade.computer:7070");
let info = client.connect().await?;
let vtxo = client.find_escrow_vtxo(&contract).await?
    .expect("escrow VTXO not found");
// Note: find_escrow_vtxo returns the first spendable VTXO. If an escrow
// address was funded more than once, use find_spendable_escrow_vtxos or
// build_release_for_outpoint/build_refund_for_outpoint to choose one.

// 3. Build release transaction (with fee outputs and chosen signer set)
let fee_outputs = vec![
    FeeOutput { address: fee_addr, amount: Amount::from_sat(100) },
];
let release = spend::build_release_tx(
    &contract,
    &vtxo,
    &buyer_addr,
    &fee_outputs,
    SignerSet::BuyerArbiter,
    info,
)?;

// 4. Sign (each party signs independently)
spend::sign_ark_tx(&mut release.ark_tx, &buyer_keypair)?;
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
client = ArkEscrow::Client.with_custom_store(
  "https://arkade.computer:7070", my_store,
  timeout_ms: 3_000, refresh_timeout_ms: 120_000
)
# Optional: update later; use 0 to disable again.
client.set_timeout_ms(3_000)
client.set_refresh_timeout_ms(120_000)
client.connect

# Create contract. `client.unilateral_exit_delay` is the raw BIP68 consensus
# sequence from the Ark server; pass it through unchanged.
contract = ArkEscrow::Contract.new(
  seller_pk, buyer_pk, arbiter_pk, client.server_pk,
  client.unilateral_exit_delay, "bitcoin"
)

# Find funded VTXO. This returns the first spendable VTXO; if the escrow was
# funded more than once, use find_spendable_escrow_vtxos and choose an outpoint.
outpoint, amount = client.find_escrow_vtxo(contract)

# Build buyer + arbiter spend (with fee outputs as [address, sats] pairs)
fee_outputs = [["ark1...fee", 100]]
ark_tx_b64, checkpoint_b64s = client.build_release(
  contract, outpoint, amount, buyer_dest_address, fee_outputs, "buyer_arbiter"
)

# Or choose a specific spendable VTXO and let the SDK load its amount from Arkade.
vtxos = client.find_spendable_escrow_vtxos(contract) # [[outpoint, amount_sats], ...]
ark_tx_b64, checkpoint_b64s = client.build_release_for_outpoint(
  contract, vtxos.first[0], buyer_dest_address, fee_outputs, "buyer_arbiter"
)

# For application-specific selection, inspect all unspent VTXOs and decide locally.
# Tuple: [outpoint, amount_sats, created_at, expires_at, spendable_offchain, recoverable, is_swept]
oldest = client.find_escrow_vtxo_statuses(contract).min_by { |v| v[2] }
raise "oldest escrow VTXO is not spendable" unless oldest && oldest[4]
ark_tx_b64, checkpoint_b64s = client.build_release_for_outpoint(
  contract, oldest[0], buyer_dest_address, fee_outputs, "buyer_arbiter"
)

# Sign and merge
signed = ArkEscrow.sign_ark_tx(ark_tx_b64, secret_key_hex)
merged = ArkEscrow.merge_sigs(signed, other_signed)

# Finalize with crash recovery
ark_txid = client.spend_escrow_offchain(
  trade_id, merged, unsigned_checkpoints, [arbiter_cps, buyer_cps]
)
```

### Refreshing recoverable VTXOs

When escrow VTXOs become recoverable, first refresh them back into the same escrow contract address. The refreshed escrow then becomes spendable again through the normal offchain signer-set flow. This avoids direct settlement outputs for fees/referrals, which may be sub-dust.

Refresh uses a separate overall deadline, defaulting to 120 seconds, for intent
registration and the complete batch ceremony. The ordinary request timeout does
not apply inside refresh. Set the deadline to accommodate the server's batch
schedule and signing time. In Rust, use `set_refresh_timeout(Some(Duration::from_secs(120)))`
or `None` to disable it. In Ruby, both store constructors accept
`refresh_timeout_ms:`, and `set_refresh_timeout_ms` changes it later; `0` disables
it. Changing `timeout_ms` does not change the refresh deadline.

A timeout stops the local wait; it does not cancel an intent already accepted by
the server or prove that the batch failed.

```ruby
# Check VTXO status
pending, vtxos, any_recoverable = client.get_escrow_vtxo_status(trade_id, contract)

# Prepare + sign + refresh using the selected signer set.
intent_b64, message_json, forfeit_b64s, cosigner_pk =
  client.prepare_refresh(contract, vtxos, "buyer_arbiter", cosigner_sk)

signed_intent, signed_forfeits = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, buyer_sk)
# ... merge arbiter + buyer sigs, then:
txid = client.refresh_escrow(signed_intent, message_json, signed_forfeits, cosigner_sk)

# Once the refreshed VTXO is visible/spendable, use build_release/build_refund.
outpoint, amount = client.find_escrow_vtxo(contract)
```

Legacy direct delegated methods remain for compatibility, but are deprecated.

### Rust logging

The Ruby extension initialises a `tracing` subscriber on load. Control verbosity via `RUST_LOG`:

```bash
RUST_LOG=ark_escrow=debug ruby my_app.rb
```

## Protocol

See [docs/protocol.md](docs/protocol.md) for the full PSBT exchange protocol.

## Spend store contract

`spend_escrow_offchain` writes a `PendingSpend` record **before** the `submit`
request leaves the process, rewrites it once the server's verified ark tx
co-signature and checkpoint signatures are in hand, marks it `finalized` after
`finalize` succeeds, and deletes it only if the server definitively rejects the
submit. Calling it again with the same `id`, or calling
`resume_pending_spend(id)`, resumes from whatever stage was recorded; a
finalized record returns its txid without a server call. The other arguments
are ignored while a record exists. The record carries a `stage` (`submitting`,
`submitted`, `finalized`), a random per-attempt `token`, and from `submitted` on
the canonical co-signed ark tx (`server_signed_ark_tx`) and the fully-signed
checkpoints.

Finalized records are **kept**: they are the parties' only evidence that the
server committed to the payout. Prune them under your own retention policy with
`remove(id)`. `get_escrow_vtxo_status` reports `pending_offchain` only for
records that are not finalized.

Records written by gem versions before the co-signature check have no
`server_signed_ark_tx`. If such a record is at `submitted` stage, resuming it
fails closed rather than releasing checkpoint signatures without evidence.

What this does and does not recover:

- Crash or failed `finalize` after `submit` returned: fully recoverable, the
  retry only finalizes.
- Crash or timeout before the server accepted `submit`: recoverable, the retry
  re-sends the same submit.
- Timeout or crash after the server accepted `submit` but before its response
  was read: **not** recoverable by this gem yet. The retry fails with
  "inputs already locked" and the record stays at `submitting` with the ark txid
  for operator follow-up. Recovering the server's checkpoint signatures needs
  `GetPendingTx` with a proof signed by both escrow parties.

A custom store must:

- Make `save(id, json)` durable before returning. The file store fsyncs.
- Return the latest JSON from `load(id)`, or `nil`.
- Optionally implement `remove_if(id, token) -> bool` as a single
  compare-and-delete (`DELETE ... WHERE id = ? AND (token = ? OR token IS NULL)`)
  and `save_if(id, json, token) -> bool` as a single compare-and-overwrite.
  Without them the gem falls back to `load`, compare, write, which is not atomic
  and only protects against a concurrent attempt if the two calls are otherwise
  serialised (e.g. by a row lock).
- Treat an `id` as bound to one ark transaction for good. Supplying a different
  transaction under an `id` that has a record is an error.
- Do not downgrade the gem while `finalized` records exist: older versions do
  not know that stage value and fail to read such records.
- Records written by older gem versions have no `stage` or `token`; they load as
  `submitted` and match any token, but see above: without `server_signed_ark_tx`
  they are not finalized automatically.

Do not run two spends for the same `id` concurrently. The store is not a lock;
the token only keeps a finished attempt from deleting another attempt's record.

## End-to-end tests

`escrow/tests/e2e_spend.rs` (release, refund, lost submit response, resume
after crash), `escrow/tests/signer_rotation.rs` (refresh and spend across a
server signer rotation) and `ruby-ext/e2e/release.rb` (the gem, end to end)
run against a real arkd. The stack comes from
the public [arkade-regtest](https://github.com/ArkLabsHQ/arkade-regtest)
submodule and the public arkd container image pinned in `.env.regtest`; no
secrets or private repositories are involved, so forks can run it unchanged.

```bash
git submodule update --init   # once
just regtest-up               # Bitcoin Core + Fulcrum + arkd, ~1 min
just e2e                      # e2e-rust + e2e-ruby
just regtest-down
```

Requires Docker and Node 20+. CI runs the same recipe in the `e2e` job.
