# CTV factory broadcast demo

End-to-end recipe for running a CTV factory broadcast against a CTV-active
Bitcoin Core node (Bitcoin Inquisition on regtest, or Mutinynet signet).

## Components

- `tools/ctv_factory_build` — C tool that builds a factory in-memory and
  prints the artefacts (funding SPK, segwit dist TX) as `key=value` lines.
- `tools/ctv_factory_demo.py` — Python orchestrator that calls the C tool,
  drives `bitcoin-cli` to fund + broadcast + CPFP, watches for confirmation.
- `tools/test_regtest_ctv_factory_demo.sh` — CI-style harness that wires it
  all together on a private regtest with Inquisition. Used as the smoke test.

## Quickstart: regtest with Bitcoin Inquisition

```bash
# 1. Download Inquisition 28.1-inq
wget https://github.com/bitcoin-inquisition/bitcoin/releases/download/v28.1-inq/bitcoin-28.1-inq-x86_64-linux-gnu.tar.gz
tar xzf bitcoin-28.1-inq-x86_64-linux-gnu.tar.gz
INQ=$PWD/bitcoin-28.1-inq

# 2. Build the CTV factory tool
cmake -B build && cmake --build build --target ctv_factory_build

# 3. Run the regtest demo (N=10 users)
bash tools/test_regtest_ctv_factory_demo.sh build "$INQ/bin" 10
```

That's the full flow. If anything fails, the harness prints the demo
script's output and the bitcoind debug.log tail.

## Quickstart: Mutinynet (public signet)

Mutinynet is a public signet with CTV (and CSFS, APO, CAT) active. It runs
Inquisition. Use it for the public-facing demo.

```bash
# 1. Same Inquisition binary as above
INQ=$PWD/bitcoin-28.1-inq

# 2. Mutinynet bitcoin.conf
mkdir -p ~/.bitcoin-mutinynet
cat > ~/.bitcoin-mutinynet/bitcoin.conf <<EOF
signet=1
[signet]
signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae
addnode=45.79.52.207:38333
dnsseed=0
server=1
rpcuser=mutinynet
rpcpassword=$(openssl rand -hex 16)
EOF

# 3. Sync (~30 minutes on a fresh node, 30-second blocks help)
$INQ/bin/bitcoind -datadir=$HOME/.bitcoin-mutinynet -daemon
$INQ/bin/bitcoin-cli -datadir=$HOME/.bitcoin-mutinynet -rpcwait getblockchaininfo

# 4. Create a wallet, get signet sats from the faucet
$INQ/bin/bitcoin-cli -datadir=$HOME/.bitcoin-mutinynet createwallet demo
ADDR=$($INQ/bin/bitcoin-cli -datadir=$HOME/.bitcoin-mutinynet -rpcwallet=demo getnewaddress "" bech32m)
echo "send signet sats to $ADDR via https://faucet.mutinynet.com"

# 5. Once funded, run the demo for 200 users
LSP_CHANGE=$($INQ/bin/bitcoin-cli -datadir=$HOME/.bitcoin-mutinynet -rpcwallet=demo getnewaddress "" bech32m)
python3 tools/ctv_factory_demo.py \
    --users 200 \
    --slot-deposit-sats 10000 \
    --build-tool ./build/ctv_factory_build \
    --bitcoin-cli "$INQ/bin/bitcoin-cli -datadir=$HOME/.bitcoin-mutinynet -rpcwallet=demo" \
    --lsp-change-address $LSP_CHANGE \
    --package-fee-sats 4000
```

Watch the dist TXID on https://mutinynet.com — 200 user outputs appear in
one block.

## Known unknowns

### V3 / TRUC for ephemeral anchor relay

**BIP-431 (TRUC) + BIP-433 (ephemeral dust)** were activated in Bitcoin Core
28.0 as policy. The relevant rules:

- An output matching the P2A pattern (`OP_1 OP_PUSHBYTES_2 0x4e73`) is
  standard **only if the parent TX is V3**
- V3 TXs are restricted to 1P1C packages (one parent, one child)
- The child must spend the parent's ephemeral anchor in the same package

Our dist TX is currently **`nVersion=2`** — the BIP-119 template hash
commits to this. If Bitcoin Inquisition 28.1-inq inherits the same policy
(which it almost certainly does), our `submitpackage [dist_tx_v2, child]`
call will be rejected with a policy error.

The regtest harness (`test_regtest_ctv_factory_demo.sh`) is exactly the
test that will reveal this. Three outcomes are possible:

1. **Submit succeeds.** Inquisition's policy is relaxed enough to accept
   V2 + P2A. Ship it.
2. **Submit fails with "TRUC-violation" / "ephemeral-anchor-not-allowed".**
   We add a V3 mode to the C library:
   - `ctv_factory_t` gets a `use_truc_v3` flag (or just hardcode V3)
   - `compute_dist_tx_th` uses `nVersion=3`
   - `ctv_factory_build_dist_tx*` writes `nVersion=3` in headers
   - All existing tests update to V3
   - Estimated effort: ~1 PR, ~200 LoC + test updates
3. **Submit fails for another reason.** Iterate based on the error.

### Alternative if V3 is too disruptive

Drop the ephemeral anchor entirely and have the dist TX pay its own fee:

- Total funding = `N * slot_deposit + dist_tx_fee_sats` (no anchor at all)
- Dist TX outputs are just N user P2TRs, no anchor
- Implicit fee = (funding amount) - (sum of outputs)
- Just `sendrawtransaction dist_tx_hex` — no CPFP, no submitpackage, no
  wallet signing of fee inputs

Simpler operationally but loses the ability to bump the fee post-funding.
For a v0 demo this is fine; for production we want CPFP.

This would require dropping the `CTV_FACTORY_ANCHOR_SATS = 240` constant
and removing the anchor output from the TH commitment — i.e. a breaking
change to PR #5/#6/#7/#8's TH computation. Not preferred.

## Deterministic seed args

The C tool uses deterministic key derivation from CLI seeds so the same
invocation produces the same factory:

| flag | meaning | default |
|---|---|---|
| `--lsp-seed-hex` | 32-byte hex; LSP's secret key | 32 × 0xA1 |
| `--user-seed-base` | 1 byte; `user_i`'s secret key = (B+i) repeated 32 times | 0xB1 |

**These are for repeatable demos, not production.** Real deployments need
real keygen.
