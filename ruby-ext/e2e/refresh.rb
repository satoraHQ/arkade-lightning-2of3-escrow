# frozen_string_literal: true

# End-to-end smoke test of the refresh path through the Ruby extension: a
# legacy four-value call (no delete proof, explicit nils) and the full form
# with the co-signed delete proof.
#
#   just build-ruby && just regtest-up && just e2e-ruby

require_relative "common"

store_dir = Dir.mktmpdir("ark-escrow-ruby-e2e")
client = ArkEscrow::Client.with_file_store(ARKD_URL, store_dir, timeout_ms: 10_000)
client.connect
server_pk = client.server_pk
delay = client.unilateral_exit_delay

seller_sk, seller_pk = keypair
buyer_sk, buyer_pk = keypair
arbiter_sk, arbiter_pk = keypair
contract = ArkEscrow::Contract.new(seller_pk, buyer_pk, arbiter_pk, server_pk, delay, "regtest")

puts "funding escrow #{contract.address}"
wallet = funded_cli_wallet(1_000_000)
regtest("ark", "--datadir", wallet, "send", "--to", contract.address, "--amount", ESCROW_SATS.to_s, "--password", "secret")
wait_for("escrow VTXO") { client.find_escrow_vtxo(contract) }

def refresh_vtxos(client, contract)
  vtxos, = client.find_refresh_vtxos(contract)
  raise "no refresh VTXOs" if vtxos.empty?

  vtxos
end

def wait_for_refreshed(client, contract, previous_outpoint)
  wait_for("refreshed VTXO") do
    outpoint, amount = client.find_escrow_vtxo(contract)
    outpoint && outpoint != previous_outpoint && amount == ESCROW_SATS
  end
end

# 1. Legacy form: four values, delete proof omitted and then passed as nil.
cosigner_sk, = keypair
intent_b64, message_json, forfeit_b64s, _cosigner_pk = client.prepare_refresh(contract, refresh_vtxos(client, contract), "buyer_arbiter", cosigner_sk)
buyer_intent, buyer_forfeits = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, buyer_sk)
arbiter_intent, arbiter_forfeits = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, arbiter_sk, nil)
intent = ArkEscrow.merge_sigs(buyer_intent, arbiter_intent)
forfeits = buyer_forfeits.zip(arbiter_forfeits).map { |b, a| ArkEscrow.merge_sigs(b, a) }
before, = client.find_escrow_vtxo(contract)
txid = client.refresh_escrow(intent, message_json, forfeits, cosigner_sk, nil, nil)
puts "legacy refresh in #{txid}"
wait_for_refreshed(client, contract, before)

# 2. Full form with the co-signed delete proof.
cosigner_sk, = keypair
intent_b64, message_json, forfeit_b64s, _cosigner_pk, delete_b64, delete_message_json =
  client.prepare_refresh(contract, refresh_vtxos(client, contract), "buyer_arbiter", cosigner_sk)
raise "no delete proof" unless delete_b64 && delete_message_json
raise "delete message #{delete_message_json}" unless JSON.parse(delete_message_json)["type"] == "delete"

buyer_intent, buyer_forfeits, buyer_delete = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, buyer_sk, delete_b64)
arbiter_intent, arbiter_forfeits, arbiter_delete = ArkEscrow.sign_refresh(intent_b64, forfeit_b64s, arbiter_sk, delete_b64)
intent = ArkEscrow.merge_sigs(buyer_intent, arbiter_intent)
forfeits = buyer_forfeits.zip(arbiter_forfeits).map { |b, a| ArkEscrow.merge_sigs(b, a) }
delete_proof = ArkEscrow.merge_sigs(buyer_delete, arbiter_delete)

# Nothing is queued yet, so a manual delete finds nothing.
raise "unexpected delete" if client.delete_refresh_intent(delete_proof, delete_message_json)

before, = client.find_escrow_vtxo(contract)
txid = client.refresh_escrow(intent, message_json, forfeits, cosigner_sk, delete_proof, delete_message_json)
puts "refresh with delete proof in #{txid}"
wait_for_refreshed(client, contract, before)

puts "ok"
