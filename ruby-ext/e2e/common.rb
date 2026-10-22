# frozen_string_literal: true

# Shared helpers for the Ruby e2e scripts.

require "json"
require "openssl"
require "tmpdir"
require "open3"
require_relative "../lib/ark_escrow"

REGTEST_DIR = ENV.fetch("REGTEST_DIR") { File.expand_path("../../regtest", __dir__) }
ARKD_URL = ENV.fetch("ARKD_URL", "http://localhost:7070")
ESCROW_SATS = 100_000

def regtest(*args)
  out, err, status = Open3.capture3("node", File.join(REGTEST_DIR, "regtest.mjs"), *args)
  raise "regtest.mjs #{args.join(' ')} failed:\n#{out}\n#{err}" unless status.success?

  out
end

# secp256k1 keypair as the gem wants it: 64-hex secret, 64-hex x-only pubkey.
def keypair
  k = OpenSSL::PKey::EC.generate("secp256k1")
  secret = k.private_key.to_s(16).rjust(64, "0")
  xonly = k.public_key.to_octet_string(:compressed).unpack1("H*")[2..]
  [secret, xonly]
end

# A funding wallet driven through the ark CLI inside the arkd container.
def funded_cli_wallet(sats)
  datadir = "/tmp/ark-escrow-ruby-e2e-#{Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)}"
  regtest("ark", "--datadir", datadir, "init", "--password", "secret",
          "--server-url", "http://localhost:7070", "--explorer", "http://mempool_web/api")
  note = regtest("arkd", "note", "--amount", sats.to_s).lines.map(&:strip).reverse.find { |l| l.start_with?("arknote") }
  raise "no arknote in output" unless note

  regtest("ark", "--datadir", datadir, "redeem-notes", "-n", note, "--password", "secret")
  datadir
end

def wait_for(what, seconds: 60)
  deadline = Time.now + seconds
  loop do
    value = yield
    return value if value

    raise "timed out waiting for #{what}" if Time.now > deadline

    sleep 1
  end
end

