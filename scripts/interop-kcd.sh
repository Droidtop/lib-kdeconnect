#!/usr/bin/env bash
# Interop with an independent protocol 8 implementation: kcd (github.com/bethropolis/kcd, Go, MIT), pinned
# by commit. The library's `peer` example and kcd's daemon run on one machine, on its own (non-loopback)
# address, and must: link (discovery, the TLS role swap, the identity re-exchange), pair from our side with
# kcd auto-accepting and both showing the same verification key, ping each way, and pass a file each way
# (the payload stream, each side once as its TLS server). Usage: scripts/interop-kcd.sh <path to kcd binary>
set -euo pipefail
KCD=$(realpath "$1")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
RUN=$(mktemp -d /tmp/kr.XXXX) # kcd's socket path must stay short (sun_path is 108 bytes)
cleanup() { kill "${PEER:-}" "${KD:-}" 2>/dev/null || true; }
trap cleanup EXIT
IP=""
if command -v ip >/dev/null; then IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1); fi
[ -n "$IP" ] || IP=$(hostname -I | awk '{print $1}')
echo "address: $IP"
export HOME=$W/home XDG_RUNTIME_DIR=$RUN XDG_CONFIG_HOME=$W/home/.config XDG_DATA_HOME=$W/home/.local/share
mkdir -p "$HOME" "$W/recv"
cargo build -q -p kdeconnect-link --example peer --manifest-path "$ROOT/Cargo.toml"
"$KCD" --log-level debug daemon > "$W/kcd.log" 2>&1 & KD=$!
sleep 3
(timeout 60 "$KCD" pair --yes > "$W/pair.log" 2>&1 &)
sleep 1
echo "to kcd $(date +%s%N)" > "$W/to-kcd.txt"
"$ROOT/target/debug/examples/peer" --name "lib-kdeconnect CI" --announce "$IP" --pair --ping "hello from lib-kdeconnect" \
  --receive-dir "$W/recv" --send-file "$W/to-kcd.txt" > "$W/peer.log" 2>&1 & PEER=$!
ok=1
for _ in $(seq 1 30); do grep -q "^paired with" "$W/peer.log" && break; sleep 1; done
ID=$(grep -o '^me: [0-9a-f]*' "$W/peer.log" | cut -d' ' -f2)
"$KCD" ping "$ID" || ok=0
echo "payload $(date +%s%N)" > "$W/share.txt"
"$KCD" share "$ID" "$W/share.txt" || ok=0
for _ in $(seq 1 15); do [ -f "$W/recv/share.txt" ] && break; sleep 1; done
sleep 1
echo "--- peer"; grep -v "mpris\|systemvolume" "$W/peer.log"
echo "--- kcd pair"; cat "$W/pair.log"
check() { if grep -q -- "$2" "$1"; then echo "ok: $3"; else echo "FAILED: $3"; ok=0; fi; }
check "$W/peer.log" "^linked: " "linked to kcd"
check "$W/peer.log" "^paired with" "paired"
KEY=$(sed -n 's/^asked to pair; key //p' "$W/peer.log")
check "$W/pair.log" "Verification code: $KEY" "kcd shows the same verification key ($KEY)"
check "$W/kcd.log" '"type": "kdeconnect.ping"' "kcd sent its ping"
check "$W/peer.log" "packet: kdeconnect.ping" "our side received kcd's ping"
check "$W/kcd.log" "notify-send\|\"plugin\": \"ping\"" "kcd received our ping"
if cmp -s "$W/share.txt" "$W/recv/share.txt"; then echo "ok: file received intact"; else echo "FAILED: file received intact"; ok=0; fi
if cmp -s "$W/to-kcd.txt" "$HOME/Downloads/kcd/to-kcd.txt"; then echo "ok: kcd received our file intact"; else echo "FAILED: kcd received our file intact"; ok=0; fi
[ "$ok" = 1 ] || { echo "--- kcd log"; tail -40 "$W/kcd.log"; exit 1; }
