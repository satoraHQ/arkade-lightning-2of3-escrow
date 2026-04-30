# Escrow PSBT Exchange Protocol

This document describes the signing protocol for releasing or refunding an escrow VTXO on Arkade.

## Parties

| Party | Role |
|-------|------|
| **Alice** | Escrow funder (buyer) |
| **Bob** | Escrow recipient (seller) |
| **Arbiter** | Trusted mediator (e.g. platform operator) |
| **Arkade Server** | Co-signer for collaborative paths |

## Contract Setup

1. Alice and Bob exchange public keys
2. The arbiter provides its public key
3. An `EscrowContract` is created with all 4 public keys + CSV delay
4. Alice funds the resulting Arkade address (the escrow VTXO)

## Release Flow (Happy Path)

The release uses the **Bob + Arbiter + Server** collaborative leaf.

The client (Bob) signs all PSBTs in a **single round-trip**. PSBT
`tap_script_sigs` are independent per-key, so Bob's and the arbiter's
signatures can be collected before the Arkade server sees the checkpoints.

```
┌─────────┐     ┌──────────┐     ┌────────┐
│  Bob    │     │ Arbiter  │     │ Arkade │
│(browser)│     │(backend) │     │ (gRPC) │
└────┬────┘     └────┬─────┘     └───┬────┘
     │               │               │
     │  1. Request release            │
     │──────────────>│               │
     │               │               │
     │               │ 2. build_release_tx()
     │               │ 3. sign_ark_tx(arbiter_sk)
     │               │ 4. sign_checkpoint(arbiter_sk) × N
     │               │               │
     │  5. All arbiter-signed PSBTs  │
     │<──────────────│               │
     │               │               │
     │ 6. sign_ark_tx(bob_sk)        │
     │ 7. sign_checkpoints(bob_sk)   │
     │ 8. Return all signed PSBTs    │
     │──────────────>│               │
     │               │               │
     │               │ 9.  merge ark_tx sigs
     │               │ 10. submit(merged_ark_tx, UNSIGNED checkpoints)
     │               │──────────────────────────────>│
     │               │               │               │
     │               │ 11. Server-signed checkpoints │
     │               │<─────────────────────────────│
     │               │               │
     │               │ 12. merge arbiter cp sigs into server cps
     │               │ 13. merge bob cp sigs into server cps
     │               │ 14. finalize(txid, fully-signed cps)
     │               │──────────────────────────────>│
     │               │               │
     │  15. Done — escrow released   │
     │<──────────────│               │
```

### Step-by-step

1. **Bob requests release** — provides his destination Arkade address
2. **Arbiter builds the release tx** — `build_release_tx()` produces unsigned `ark_tx` + `checkpoint_txs` PSBTs
3. **Arbiter signs ark_tx** — `sign_ark_tx(ark_tx, arbiter_sk)`
4. **Arbiter signs checkpoints** — `sign_checkpoint(cp, arbiter_sk)` for each
5. **Arbiter returns all PSBTs** — arbiter-signed `ark_tx` + arbiter-signed checkpoints
6. **Bob signs ark_tx** — `sign_ark_tx(ark_tx, bob_sk)` or TS equivalent
7. **Bob signs checkpoints** — `sign_checkpoint(cp, bob_sk)` for each
8. **Bob returns all signed PSBTs** to the arbiter
9. **Arbiter merges ark_tx** — `merge_ark_tx_sigs(arbiter_signed, bob_signed)`
10. **Arbiter submits to Arkade** — `submit(merged_ark_tx, UNSIGNED_checkpoints)` via gRPC. **Only unsigned checkpoints are sent** — checkpoint signatures must not be revealed to the server before it co-signs the ark_tx.
11. **Arkade returns server-signed checkpoints** — server adds its signatures to the checkpoints
12. **Arbiter merges its checkpoint sigs** into the server-signed copies
13. **Arbiter merges Bob's checkpoint sigs** into the result
14. **Arbiter finalizes** — `finalize(ark_txid, fully_signed_checkpoints)` via gRPC
15. **Done** — escrow VTXO is spent, Bob receives funds at destination

### Security invariant

> Checkpoint signatures (arbiter's and Bob's) are **never** sent to the
> Arkade server before the server co-signs the ark_tx. The `submit` call
> only includes unsigned checkpoints. This prevents the server from
> broadcasting checkpoints unilaterally before committing to the ark
> transaction.

## Refund Flow

Same protocol but uses the **Alice + Arbiter + Server** collaborative leaf via `build_refund_tx()`. Alice signs instead of Bob, and funds return to Alice's address.

## Refresh Flow for Recoverable VTXOs

If the escrow VTXO is recoverable rather than spendable, do not release/refund it directly via settlement. Settlement cannot create sub-dust outputs, while release may include small platform/referral fee outputs.

Instead, first **refresh** the escrow contract:

1. Arbiter calls `prepare_refresh(contract, vtxos, RefreshPath::Release, ...)` for release, or `RefreshPath::Refund` for refund.
2. The refresh intent creates a single output back to the same escrow address for the full input sum.
3. Bob signs the refresh for release; Alice signs it for refund. The arbiter also signs.
4. Arbiter calls `refresh_escrow(...)`.
5. Once the refreshed escrow VTXO is visible/spendable, run the normal release/refund flow above.

This means recoverable release/refund requires two signing rounds: one refresh round, then one normal offchain release/refund round.

Legacy direct delegated release APIs remain available for compatibility, but are deprecated.

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
await api("POST", `/release/sign`, {
  signed_ark_tx: signedPsbt,
  signed_checkpoints: signedCheckpoints,
});
```
