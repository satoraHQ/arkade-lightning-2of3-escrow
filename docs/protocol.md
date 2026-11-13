# Escrow PSBT Exchange Protocol

This document describes the signing protocol for spending an escrow VTXO on Arkade using named signer sets.

## Parties

| Party | Role |
|-------|------|
| **Seller** | Escrow funder |
| **Buyer** | Escrow recipient |
| **Arbiter** | Trusted mediator (e.g. platform operator) |
| **Arkade Server** | Co-signer for collaborative paths |

## Contract Setup

1. Seller and Buyer exchange public keys
2. The arbiter provides its public key
3. An `EscrowContract` is created with all 4 public keys + CSV delay
4. Seller funds the resulting Arkade address (the escrow VTXO)

## Buyer + Arbiter Flow

This flow uses the **Buyer + Arbiter + Server** collaborative leaf.

The client (Buyer) signs all PSBTs in a **single round-trip**. PSBT
`tap_script_sigs` are independent per-key, so Buyer's and the arbiter's
signatures can be collected before the Arkade server sees the checkpoints.

```
┌─────────┐     ┌──────────┐     ┌────────┐
│  Buyer    │     │ Arbiter  │     │ Arkade │
│(browser)│     │(backend) │     │ (gRPC) │
└────┬────┘     └────┬─────┘     └───┬────┘
     │               │               │
     │  1. Request buyer+arbiter spend│
     │──────────────>│               │
     │               │               │
     │               │ 2. build_release_tx(..., signer_set)
     │               │ 3. sign_ark_tx(arbiter_sk)
     │               │ 4. sign_checkpoint(arbiter_sk) × N
     │               │               │
     │  5. All arbiter-signed PSBTs  │
     │<──────────────│               │
     │               │               │
     │ 6. sign_ark_tx(buyer_sk)        │
     │ 7. sign_checkpoints(buyer_sk)   │
     │ 8. Return all signed PSBTs    │
     │──────────────>│               │
     │               │               │
     │               │ 9.  merge ark_tx sigs
     │               │ 10. merge arbiter + buyer cp sigs into the checkpoints
     │               │ 11. submit(merged_ark_tx, SIGNED checkpoints)
     │               │──────────────────────────────>│
     │               │               │               │
     │               │ 12. co-signed ark_tx + fully-signed checkpoints
     │               │     (arkd has finalized at this point)
     │               │<─────────────────────────────│
     │               │               │
     │               │ 13. verify server sig on ark_tx (leaf's server key)
     │               │      → error if missing/invalid
     │               │ 14. only if not finalized: finalize(txid, fully-signed cps)
     │               │──────────────────────────────>│
     │               │               │
     │  15. Done — escrow spent      │
     │<──────────────│               │
```

### Step-by-step

1. **Buyer requests a buyer + arbiter spend** — provides their destination Arkade address
2. **Arbiter builds the transaction** — `build_release_tx(..., signer_set)` produces unsigned `ark_tx` + `checkpoint_txs` PSBTs
3. **Arbiter signs ark_tx** — `sign_ark_tx(ark_tx, arbiter_sk)`
4. **Arbiter signs checkpoints** — `sign_checkpoint(cp, arbiter_sk)` for each
5. **Arbiter returns all PSBTs** — arbiter-signed `ark_tx` + arbiter-signed checkpoints
6. **Buyer signs ark_tx** — `sign_ark_tx(ark_tx, buyer_sk)` or TS equivalent
7. **Buyer signs checkpoints** — `sign_checkpoint(cp, buyer_sk)` for each
8. **Buyer returns all signed PSBTs** to the arbiter
9. **Arbiter merges ark_tx** — `merge_ark_tx_sigs(arbiter_signed, buyer_signed)`
10. **Arbiter merges both parties' checkpoint sigs** into the checkpoints
11. **Arbiter submits to Arkade** — `submit(merged_ark_tx, signed_checkpoints)` via gRPC (one-shot submit)
12. **Arkade returns the co-signed ark_tx and the fully-signed checkpoints** — arkd verifies the party signatures, adds its own and finalizes within this call; it signals that by returning the checkpoints still carrying the party signatures. The client only takes that as final if every key of each checkpoint's spend leaf, the server's included, has a valid signature; otherwise it finalizes separately. A one-shot submit the server rejects leaves nothing pending on the server. A timeout or a failed check on the client side says nothing about the server: the spend may already be final.
13. **Arbiter verifies the server's co-signature** on the ark_tx (`verify_server_ark_tx_sig`): same unsigned transaction, and a valid `Default`-sighash Schnorr signature by the server key named in the escrow leaf being spent. Keys the server merely announces do not count. If the check fails, the call fails and the record stays at `submitting`; on a one-shot server the spend may nevertheless be final, and a retry with the same id recovers it from the indexer. The canonical co-signed ark_tx (local PSBT plus the verified server signature) is kept in the spend record as the parties' evidence of the server's commitment.
14. **Only if the server did not finalize: Arbiter finalizes** — not expected from arkd, which always runs a version with one-shot submit. If a response nevertheless comes back without fully-signed checkpoints, or an accepted spend is being recovered after a lost response, the client calls `finalize(ark_txid, fully_signed_checkpoints)` so that nothing is left pending
15. **Done** — escrow VTXO is spent, buyer receives funds at destination

### One-shot submit and what it trusts

> Escrow spends use Arkade's one-shot submit: the checkpoints are sent fully
> party-signed in `submit` and the server finalizes in the same call. No
> transaction is left pending between `submit` and `finalize`, which is
> where a crashed or interrupted client used to strand a spend.
>
> The price: checkpoint signatures (arbiter's and Buyer's) reach the Arkade
> server **before** it returns its co-signature on the ark_tx. A server that
> kept them without committing to the ark transaction could broadcast the
> checkpoints unilaterally. Earlier versions withheld the checkpoint
> signatures until the co-signature had been verified locally (HH-ARK-017);
> that ordering is given up here. The co-signature is still verified on the
> response and kept as evidence, but it no longer gates the release of the
> checkpoint signatures.

## Seller + Arbiter Flow

Same protocol, but uses the **Seller + Arbiter + Server** collaborative leaf via `build_refund_tx(..., signer_set)`. Seller signs instead of buyer, and funds go to the seller destination.

## Refresh Flow for Recoverable VTXOs

If the escrow VTXO is recoverable rather than spendable, refresh it instead of using direct settlement. Settlement cannot create sub-dust outputs, while the buyer + arbiter flow may include small platform/referral fee outputs.

Instead, first **refresh** the escrow contract:

1. Arbiter calls `prepare_refresh(contract, vtxos, signer_set, ...)` with `SignerSet::BuyerArbiter`, `SignerSet::SellerArbiter`, or `SignerSet::SellerBuyer`.
2. The refresh intent creates a single output back to the same escrow address for the full input sum.
3. The parties in the selected signer set sign the refresh.
4. Arbiter calls `refresh_escrow(...)`.
5. Once the refreshed escrow VTXO is visible/spendable, run the normal offchain signer-set flow above.

This means recoverable spends require two signing rounds: one refresh round, then one normal offchain spend round.

Legacy direct delegated buyer + arbiter APIs remain available for compatibility, but are deprecated.

## Unilateral Exit

If the Arkade server is unavailable, any collaborative path can be replaced by its unilateral counterpart after the CSV delay expires. The unilateral paths require only 2 of the 3 user parties (no server signature needed).

## PSBT Format

- All PSBTs are exchanged as **base64-encoded strings**
- The ark_tx PSBT always has the escrow VTXO as **input 0**
- Signatures are **Schnorr tapscript signatures** (BIP 341)
- Merging combines `tap_script_sigs` from both PSBTs
- The `unsigned_tx` is identical before and after server signing — only `tap_script_sigs` differ

## TypeScript (Frontend) Signing

The `@lendasat/lendaswap-sdk-pure` package provides helpers:

```typescript
import {
  signEscrowArkTx,
  signEscrowCheckpoints,
} from "@lendasat/lendaswap-sdk-pure";

// Sign everything in one go
const { signedPsbt, txid } = signEscrowArkTx(arkTxPsbtB64, secretKey);
const signedCheckpoints = signEscrowCheckpoints(checkpointPsbtB64s, secretKey);

// Send both back to the arbiter
await api("POST", `/buyer-arbiter/sign`, {
  signed_ark_tx: signedPsbt,
  signed_checkpoints: signedCheckpoints,
});
```
