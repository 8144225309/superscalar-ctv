#!/usr/bin/env bash
#
# test_ctv_node_detection.sh — live two-node test of superscalar-ctv's
# --ctv-mode node-capability check (CTV arc, feature 1).
#
#   Phase 1: a VANILLA Bitcoin Core regtest node (no CTV) must be REFUSED.
#            OP_CHECKTEMPLATEVERIFY is OP_NOP4 there, so a CTV output would be
#            anyone-can-spend; --ctv-mode must exit non-zero and say so.
#   Phase 2: a Bitcoin INQUISITION regtest node (CTV enforced) must be allowed
#            to PROCEED. The detector must recognize the checktemplateverify
#            deployment in getdeploymentinfo and not refuse.
#
# This is the real-node counterpart to tests/test_ctv_detect.c, which only
# feeds the parser hand-written mock JSON. It proves the detector handles the
# ACTUAL getdeploymentinfo shape a real node returns — the one thing the unit
# mocks cannot guarantee.
#
# Usage: test_ctv_node_detection.sh BUILD_DIR INQ_BIN_DIR
#   BUILD_DIR    dir containing the built superscalar_lsp
#   INQ_BIN_DIR  dir containing the Inquisition bitcoind (e.g. inq/bin)
# Assumes vanilla bitcoind + bitcoin-cli on PATH and ~/.bitcoin/bitcoin.conf
# configured for regtest on rpcport 18443. Only one node runs at a time (they
# share the default datadir; the regtest chainstate is wiped between phases).

set -euo pipefail

BUILD="${1:?usage: $0 BUILD_DIR INQ_BIN_DIR}"
INQ_BIN="${2:?usage: $0 BUILD_DIR INQ_BIN_DIR}"
LSP="$BUILD/superscalar_lsp"
REGDIR="$HOME/.bitcoin/regtest"

[ -x "$LSP" ] || { echo "ERROR: no executable superscalar_lsp at $LSP"; exit 1; }
[ -x "$INQ_BIN/bitcoind" ] || { echo "ERROR: no Inquisition bitcoind at $INQ_BIN/bitcoind"; exit 1; }

cleanup() { bitcoin-cli -regtest stop >/dev/null 2>&1 || true; sleep 2; }
trap cleanup EXIT

wait_rpc() {
  for _ in $(seq 1 30); do
    if bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "ERROR: bitcoind RPC did not come up"; return 1
}

LSP_OUT="${TMPDIR:-/tmp}/ctv_lsp_out.txt"

# Run `superscalar_lsp --ctv-mode` against the live regtest node.
# Sets globals OUT (combined stdout+stderr) and RC (exit code).
#
# Output goes to a FILE, not a command-substitution pipe. On the PROCEED path
# the LSP runs past the CTV check (daemon/worker); a child inherits the stdout
# fd, so a $(...) pipe would never reach EOF and the read would block until the
# job timeout. A regular file has no such dependency. stdbuf forces line
# buffering so the early CTV-decision lines are flushed before `timeout` stops
# the process; --kill-after SIGKILLs anything ignoring SIGTERM; pkill reaps a
# daemonized survivor so it can't hold the RPC/port into the next phase.
run_ctv_mode() {
  set +e
  : > "$LSP_OUT"
  timeout --kill-after=5 --signal=TERM 30 \
    stdbuf -oL -eL "$LSP" --ctv-mode --network regtest --port 19099 \
    > "$LSP_OUT" 2>&1
  RC=$?
  pkill -f "superscalar_lsp .*--ctv-mode" >/dev/null 2>&1 || true
  set -e
  OUT="$(cat "$LSP_OUT")"
  sleep 1
}

show_ctv_deployment() {
  bitcoin-cli -regtest getdeploymentinfo 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin).get("deployments", {})
except Exception:
    print("  (could not parse getdeploymentinfo)"); sys.exit(0)
ctv = d.get("checktemplateverify") or d.get("ctv")
print("  deployments:", ", ".join(sorted(d.keys())) or "(none)")
print("  checktemplateverify:", json.dumps(ctv) if ctv else "(NOT PRESENT)")
' || true
}

echo "######################################################################"
echo "# Phase 1: VANILLA Bitcoin Core regtest  ->  MUST REFUSE"
echo "######################################################################"
bitcoind -regtest -daemon -fallbackfee=0.00001 >/dev/null
wait_rpc
bitcoin-cli -regtest createwallet ctvtest >/dev/null 2>&1 \
  || bitcoin-cli -regtest loadwallet ctvtest >/dev/null 2>&1 || true
bitcoin-cli -regtest -generate 101 >/dev/null
echo "--- vanilla getdeploymentinfo (CTV expected ABSENT) ---"
show_ctv_deployment
run_ctv_mode
echo "--- superscalar_lsp --ctv-mode output (vanilla), exit=$RC ---"
echo "$OUT"
bitcoin-cli -regtest stop >/dev/null 2>&1 || true; sleep 2
[ "$RC" -ne 0 ] \
  || { echo "FAIL: --ctv-mode did NOT refuse a vanilla node (exit 0)"; exit 1; }
echo "$OUT" | grep -qi "does not enforce CTV" \
  || { echo "FAIL: vanilla refusal missing the anyone-can-spend message"; exit 1; }
echo "PASS: vanilla node refused as intended (exit $RC)."
rm -rf "$REGDIR"

echo "######################################################################"
echo "# Phase 2: Bitcoin INQUISITION regtest (CTV)  ->  MUST PROCEED"
echo "######################################################################"
"$INQ_BIN/bitcoind" -regtest -daemon -fallbackfee=0.00001 >/dev/null
wait_rpc
bitcoin-cli -regtest createwallet ctvtest >/dev/null 2>&1 || true
# Inquisition activates CTV "heretically" from genesis (height 0, active:true),
# so no BIP9 ramp is needed; these blocks just fund the wallet.
bitcoin-cli -regtest -generate 101 >/dev/null
echo "--- inquisition getdeploymentinfo (CTV expected PRESENT) ---"
show_ctv_deployment
run_ctv_mode
echo "--- superscalar_lsp --ctv-mode output (inquisition), exit=$RC ---"
echo "$OUT"
echo "    (exit 124 = timeout killing the daemon after it PROCEEDED — expected)"
bitcoin-cli -regtest stop >/dev/null 2>&1 || true; sleep 2
if echo "$OUT" | grep -qi "does not enforce CTV"; then
  echo "FAIL: --ctv-mode REFUSED a CTV (Inquisition) node — the detector"
  echo "      mis-reads the real getdeploymentinfo shape. Inspect the dump above."
  exit 1
fi
echo "$OUT" | grep -Eqi "deployment status = (active|signaling|defined)" \
  || { echo "FAIL: detector reported no CTV status on the Inquisition node"; exit 1; }
echo "$OUT" | grep -qi "proceeding" \
  || { echo "FAIL: --ctv-mode did not proceed on the CTV node"; exit 1; }
echo "PASS: Inquisition (CTV) node proceeded as intended."

echo
echo "######################################################################"
echo "# ALL CTV NODE-DETECTION CHECKS PASSED"
echo "#   vanilla Bitcoin Core 28.1  -> REFUSE (anyone-can-spend guard)"
echo "#   Bitcoin Inquisition 28.1   -> PROCEED (CTV enforced)"
echo "######################################################################"
