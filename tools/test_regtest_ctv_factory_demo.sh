#!/usr/bin/env bash
#
# test_regtest_ctv_factory_demo.sh — end-to-end CTV factory broadcast test.
#
# Stands up a Bitcoin Inquisition regtest node (CTV active), funds a wallet,
# runs tools/ctv_factory_demo.py to build + fund + fire a small CTV factory
# (default N=10 users), and asserts the dist TX confirmed with the expected
# number of user UTXOs.
#
# Background block miner runs concurrently so the demo's wait_for_tx_in_block
# polling loops actually see confirmations.  This stays out of the demo
# script's awareness (the demo doesn't know it's on regtest).
#
# Usage: test_regtest_ctv_factory_demo.sh BUILD_DIR INQ_BIN_DIR [N_USERS]
#   BUILD_DIR    dir containing built ctv_factory_build
#   INQ_BIN_DIR  dir containing Inquisition bitcoind (e.g. inq/bin)
#   N_USERS      number of factory user slots (default 10; must be <=200)
#
# Exit 0 = PASS, non-zero = FAIL.

set -euo pipefail

BUILD="${1:?usage: $0 BUILD_DIR INQ_BIN_DIR [N_USERS]}"
INQ_BIN="${2:?usage: $0 BUILD_DIR INQ_BIN_DIR [N_USERS]}"
N_USERS="${3:-10}"

TOOL="$BUILD/ctv_factory_build"
DEMO="$(dirname "$0")/ctv_factory_demo.py"
[ -x "$TOOL" ] || { echo "ERROR: no executable $TOOL"; exit 1; }
[ -x "$INQ_BIN/bitcoind" ] || { echo "ERROR: no Inquisition bitcoind at $INQ_BIN/bitcoind"; exit 1; }
[ -f "$DEMO" ] || { echo "ERROR: no demo script at $DEMO"; exit 1; }

# Isolated datadir + port pair so this never collides with the shared
# regtest bitcoind on :18443 used by other tests.
TAG="ctv_factory_demo"
DATADIR="${DATADIR:-/tmp/ss_rt_${TAG}_bitcoind}"
RPCPORT="${RPCPORT:-29701}"
P2PPORT="${P2PPORT:-29702}"
RPCUSER="ctvdemo"
RPCPASS="ctvdemopass"
WALLET="ctv_demo_wallet"
LOG="/tmp/ss_rt_${TAG}.log"
MINER_PID_FILE="/tmp/ss_rt_${TAG}_miner.pid"

BCLI="$INQ_BIN/bitcoin-cli -regtest -datadir=$DATADIR -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT"
BCLI_W="$BCLI -rpcwallet=$WALLET"

pkill -9 -f "bitcoind.*-datadir=$DATADIR" 2>/dev/null || true
[ -f "$MINER_PID_FILE" ] && kill -9 "$(cat "$MINER_PID_FILE")" 2>/dev/null || true
rm -rf "$DATADIR" "$LOG" "$MINER_PID_FILE"
mkdir -p "$DATADIR"

cleanup() {
    local rc=$?
    [ -f "$MINER_PID_FILE" ] && kill -9 "$(cat "$MINER_PID_FILE")" 2>/dev/null || true
    pkill -9 -f "bitcoind.*-datadir=$DATADIR" 2>/dev/null || true
    rm -rf "$DATADIR" "$MINER_PID_FILE"
    return $rc
}
trap cleanup EXIT INT TERM

cat > "$DATADIR/bitcoin.conf" <<CONF
regtest=1
server=1
listen=1
discover=0
fallbackfee=0.00001
txindex=1
[regtest]
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPCPORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=$P2PPORT
bind=127.0.0.1:$P2PPORT
CONF

echo "=== CTV factory demo regtest test ==="
echo "  inquisition_bitcoind=$INQ_BIN/bitcoind"
echo "  datadir=$DATADIR  rpc=$RPCPORT  p2p=$P2PPORT"
echo "  n_users=$N_USERS"

"$INQ_BIN/bitcoind" -datadir="$DATADIR" -daemon -pid="$DATADIR/bitcoind.pid" 2>&1 | tee -a "$LOG" >/dev/null
sleep 1

for i in $(seq 1 30); do
    $BCLI getblockchaininfo >/dev/null 2>&1 && break
    sleep 1
done
$BCLI getblockchaininfo >/dev/null 2>&1 || {
    echo "FAIL: bitcoind never came up"
    tail -20 "$DATADIR/regtest/debug.log" 2>/dev/null
    exit 1
}

# Verify CTV is actually active on this binary.
CTV_STATUS=$($BCLI getdeploymentinfo 2>/dev/null | python3 -c 'import sys,json
d=json.load(sys.stdin).get("deployments",{})
c=d.get("checktemplateverify") or d.get("ctv") or {}
print(c.get("active","missing"))')
if [ "$CTV_STATUS" != "True" ] && [ "$CTV_STATUS" != "true" ]; then
    echo "FAIL: CTV not active on this node (status=$CTV_STATUS)"
    echo "      This script requires Bitcoin Inquisition, not vanilla Core."
    exit 1
fi
echo "  CTV active: yes"

$BCLI createwallet "$WALLET" >/dev/null 2>&1 || $BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
ADDR=$($BCLI_W getnewaddress "" bech32m)
LSP_CHANGE_ADDR=$($BCLI_W getnewaddress "" bech32m)
echo "  Mining 110 blocks to mature coinbase..."
$BCLI_W generatetoaddress 110 "$ADDR" >/dev/null
BAL=$($BCLI_W getbalance)
echo "  Wallet balance: $BAL BTC"

# Background block miner: 1 block every 2s so the demo's wait_for_tx_in_block
# loops see confirmations within their 15-second poll period.
(
    while sleep 2; do
        $BCLI_W generatetoaddress 1 "$ADDR" >/dev/null 2>&1 || break
    done
) &
echo $! > "$MINER_PID_FILE"
echo "  Background miner started (pid=$(cat "$MINER_PID_FILE"))"

# Run the demo script, capturing all output.  We pass a BCLI command that
# includes the wallet flag so sendtoaddress targets the funded wallet.
echo ""
echo "--- running ctv_factory_demo.py for $N_USERS users ---"
set +e
DEMO_OUT="/tmp/ss_rt_${TAG}_demo.log"
python3 "$DEMO" \
    --users "$N_USERS" \
    --slot-deposit-sats 10000 \
    --build-tool "$TOOL" \
    --bitcoin-cli "$INQ_BIN/bitcoin-cli -regtest -datadir=$DATADIR -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT -rpcwallet=$WALLET" \
    --lsp-change-address "$LSP_CHANGE_ADDR" \
    --dist-tx-fee-sats 4000 \
    2>&1 | tee "$DEMO_OUT"
DEMO_RC=${PIPESTATUS[0]}
set -e
echo "  demo exit: $DEMO_RC"

# Stop the background miner before final verification.
kill -9 "$(cat "$MINER_PID_FILE")" 2>/dev/null || true
rm -f "$MINER_PID_FILE"

if [ "$DEMO_RC" -ne 0 ]; then
    echo ""
    echo "=== FAIL: demo script exited non-zero ==="
    tail -40 "$DEMO_OUT"
    exit 1
fi

# Extract the dist_txid from the demo output and verify on-chain.
DIST_TXID=$(grep -E "^\s+dist_txid\s+=" "$DEMO_OUT" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [ -z "$DIST_TXID" ]; then
    echo "FAIL: could not extract dist_txid from demo output"
    tail -20 "$DEMO_OUT"
    exit 1
fi
echo "  dist_txid: $DIST_TXID"

# Mine a couple more blocks for finality + assert the dist TX is confirmed.
$BCLI_W generatetoaddress 3 "$ADDR" >/dev/null
CONFIRMS=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get("confirmations",0))' || echo 0)
if [ "$CONFIRMS" -lt 1 ]; then
    echo "FAIL: dist TX has $CONFIRMS confirmations"
    exit 1
fi
echo "  dist TX confirmations: $CONFIRMS"

# Verify the right number of user outputs were created.
N_VOUT=$($BCLI getrawtransaction "$DIST_TXID" true | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["vout"]))')
EXPECTED_VOUT=$((N_USERS + 1))   # N users + 1 anchor
if [ "$N_VOUT" -ne "$EXPECTED_VOUT" ]; then
    echo "FAIL: dist TX has $N_VOUT outputs, expected $EXPECTED_VOUT (N_USERS=$N_USERS + 1 anchor)"
    exit 1
fi
echo "  dist TX has $N_VOUT outputs (expected $EXPECTED_VOUT) — $N_USERS users + 1 anchor"

echo ""
echo "=== PASS: CTV factory demo end-to-end on regtest with N=$N_USERS users ==="
