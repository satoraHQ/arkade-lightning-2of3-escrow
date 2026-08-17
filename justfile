set dotenv-load := true

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace

ci: fmt-check clippy test

signer-rotation-e2e:
    test -n "$REGTEST_DIR" || (echo "REGTEST_DIR must be set" >&2; exit 1)
    test -f "$REGTEST_DIR/regtest.mjs" || (echo "REGTEST_DIR/regtest.mjs must exist" >&2; exit 1)
    REGTEST_DIR="$(realpath "$REGTEST_DIR")" cargo test -p ark-escrow --test signer_rotation -- --ignored --nocapture
