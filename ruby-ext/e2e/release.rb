# frozen_string_literal: true

# End-to-end smoke test of the Ruby extension against a live arkade-regtest
# stack: fund a 2-of-3 escrow, release it to a buyer destination through the
# gem exactly as the exchange does, and check the funds arrive.
#
#   just build-ruby && just regtest-up && just e2e-ruby

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

store_dir = Dir.mktmpdir("ark-escrow-ruby-e2e")
client = ArkEscrow::Client.with_file_store(ARKD_URL, store_dir, timeout_ms: 10_000)
client.connect
server_pk = client.server_pk
delay = client.unilateral_exit_delay

seller_sk, seller_pk = keypair
buyer_sk, buyer_pk = keypair
arbiter_sk, arbiter_pk = keypair
contract = ArkEscrow::Contract.new(seller_pk, buyer_pk, arbiter_pk, server_pk, delay, "regtest")

_, dest_pk = keypair
dest_a = keypair[1]
dest_b = keypair[1]
destination = ArkEscrow::Contract.new(dest_a, dest_b, dest_pk, server_pk, delay, "regtest")

puts "funding escrow #{contract.address}"
wallet = funded_cli_wallet(1_000_000)
regtest("ark", "--datadir", wallet, "send", "--to", contract.address, "--amount", ESCROW_SATS.to_s, "--password", "secret")

outpoint, amount = wait_for("escrow VTXO") { client.find_escrow_vtxo(contract) }
raise "unexpected escrow amount #{amount}" unless amount == ESCROW_SATS

puts "building release of #{outpoint}"
ark_tx, checkpoints = client.build_release(contract, outpoint, amount, destination.address, [], "buyer_arbiter")

# Buyer and arbiter sign independently; the arbiter merges the ark tx sigs.
buyer_ark = ArkEscrow.sign_ark_tx(ark_tx, buyer_sk)
arbiter_ark = ArkEscrow.sign_ark_tx(ark_tx, arbiter_sk)
merged_ark = ArkEscrow.merge_sigs(buyer_ark, arbiter_ark)
buyer_cps = checkpoints.map { |cp| ArkEscrow.sign_checkpoint(cp, buyer_sk) }
arbiter_cps = checkpoints.map { |cp| ArkEscrow.sign_checkpoint(cp, arbiter_sk) }

trade_id = "ruby-e2e-#{outpoint}"
txid = client.spend_escrow_offchain(trade_id, merged_ark, checkpoints, [buyer_cps, arbiter_cps])
puts "released in #{txid}"
raise "txid is not 64 hex chars: #{txid.inspect}" unless txid.match?(/\A\h{64}\z/)

_, received = wait_for("funds at destination") { client.find_escrow_vtxo(destination) }
raise "destination got #{received}, expected #{ESCROW_SATS}" unless received == ESCROW_SATS

# Resuming a finished spend is idempotent and does not touch the server.
resumed = client.resume_pending_spend(trade_id)
raise "resume returned #{resumed.inspect}" unless [nil, txid].include?(resumed)

pending, = client.get_escrow_vtxo_status(trade_id, contract)
raise "spend still reported pending" if pending

puts "ok"
