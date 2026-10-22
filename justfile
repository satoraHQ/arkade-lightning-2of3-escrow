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

# End-to-end tests against a running arkade-regtest stack. Defaults to the
# `regtest` submodule; override REGTEST_DIR to point elsewhere.
# Bring the stack up first: `just regtest-up`.
e2e:
    REGTEST_DIR="$(realpath "${REGTEST_DIR:-regtest}")" && test -f "$REGTEST_DIR/regtest.mjs" || (echo "regtest.mjs not found; run: git submodule update --init" >&2; exit 1)
    REGTEST_DIR="$(realpath "${REGTEST_DIR:-regtest}")" cargo test -p ark-escrow --test signer_rotation -- --ignored --test-threads=1 --nocapture

regtest-up:
    node regtest/regtest.mjs start --env .env.regtest --profile ark

regtest-down:
    node regtest/regtest.mjs clean

# Kept for compatibility.
signer-rotation-e2e: e2e
