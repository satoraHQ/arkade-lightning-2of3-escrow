# frozen_string_literal: true

# Checks that network calls release the GVL and that the spend-store
# callbacks still run as Ruby code. Needs no arkd: the "server" is a TCP
# listener that accepts and never answers, so every call waits for its timeout.
#
#   just test-ruby

require "socket"
require "timeout"
require_relative "../lib/ark_escrow"

TIMEOUT_MS = 1000

def check(name)
  raise "FAILED: #{name}" unless yield

  puts "ok: #{name}"
end

class Store
  attr_reader :loaded

  def initialize = @loaded = []
  def save(*) = nil
  def remove(*) = nil

  def load(id)
    raise ArgumentError, "store is down" if id == "boom"

    @loaded << id
    nil
  end
end

listener = TCPServer.new("127.0.0.1", 0)
url = "http://127.0.0.1:#{listener.addr[1]}"
store = Store.new
client = ArkEscrow::Client.with_custom_store(url, store, timeout_ms: TIMEOUT_MS)

ticks = 0
Thread.new { loop { ticks += 1; sleep 0.01 } }
sleep 0.1

before = ticks
error = begin
  client.connect
rescue RuntimeError => e
  e.message
end
check("connect times out against a silent server") { error.to_s.include?("timed out") }
check("other Ruby threads run during a network call (#{ticks - before} ticks)") { ticks - before > TIMEOUT_MS / 10 / 2 }

check("store callback runs inside a call") { client.resume_pending_spend("42").nil? && store.loaded == ["42"] }

error = begin
  client.resume_pending_spend("boom")
rescue RuntimeError => e
  e.message
end
check("store exception surfaces as an error") { error.to_s.include?("store is down") }

# With the client lock held across connect this hangs: one thread waits for
# the lock with the GVL, the other for the GVL with the lock.
connecting = Thread.new { client.connect rescue nil }
sleep 0.1
client.set_timeout_ms(TIMEOUT_MS)
connecting.join
check("connect does not block other calls on the same client") { true }

started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
error = begin
  Timeout.timeout(0.2) { client.connect }
rescue Timeout::Error, RuntimeError => e
  e.class
end
elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
check("an interrupt is delivered after the call returns (#{error}, #{elapsed.round(1)}s)") do
  error == Timeout::Error && elapsed >= TIMEOUT_MS / 1000.0
end
