#!/usr/bin/env python3
"""
ctv_factory_demo.py — drive a CTV factory broadcast end-to-end against
a bitcoind running on a CTV-active network (Mutinynet signet, regtest
with -vbparams, etc.).

Flow:
  1. Build factory in-memory via ctv_factory_build (the C tool)
  2. Derive bech32m address from funding_spk_hex (via decodescript)
  3. bitcoin-cli sendtoaddress  → fund the factory
  4. Wait for the funding TX to confirm; pick the right vout
  5. Re-run ctv_factory_build with the funding outpoint to get the
     full segwit dist TX with witness embedded
  6. Build a CPFP child that spends the P2A anchor + an LSP wallet input
     and pays the package fee back to the LSP's change address
  7. submitpackage [dist_tx_hex, cpfp_child_hex]
  8. Wait for the dist TX to confirm

After step 8, N user UTXOs are spendable on-chain.

NOTE — this script has been correctness-reviewed but has NOT yet been
exercised against a live bitcoind.  Treat the first run as a guided
hand-test.  Expected sticking points:

  - decodescript's address-extraction shape varies slightly across
    Bitcoin Core minor versions
  - fundrawtransaction with a non-wallet input (the P2A anchor) needs
    `input_weights` to avoid fee mis-estimation; some older versions
    don't expose this and require a manual fee
  - signrawtransactionwithwallet may report complete=false for the
    anchor input even though anyone-can-spend doesn't need a signature
  - Mutinynet's standardness policy may require V3 (TRUC) for ephemeral
    anchor relay; our dist TX is currently V2.  If submitpackage fails
    with a policy reason, we add a V3 mode to the C library

Usage:
    python3 tools/ctv_factory_demo.py \\
        --users 200 \\
        --slot-deposit-sats 10000 \\
        --build-tool ./build/ctv_factory_build \\
        --bitcoin-cli "bitcoin-cli -signet -rpcuser=X -rpcpassword=Y" \\
        --lsp-change-address tb1p... \\
        --package-fee-sats 2000
"""

import argparse
import json
import subprocess
import sys
import time


def run_build_tool(tool_path, extra_args):
    """Run ctv_factory_build with the given args and parse key=value lines."""
    cmd = [tool_path] + extra_args
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"ctv_factory_build failed (rc={p.returncode}):\n")
        sys.stderr.write(p.stderr)
        sys.exit(1)
    out = {}
    for line in p.stdout.strip().split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def cli(cli_args, method, *params):
    """Call bitcoin-cli <cli_args> <method> <param>...

    Non-string params are JSON-encoded.  Returns parsed JSON or raw text."""
    cmd = list(cli_args) + [method]
    for p in params:
        cmd.append(p if isinstance(p, str) else json.dumps(p))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {method} failed: {r.stderr.strip()}")
    out = r.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def decode_spk_to_address(cli_args, spk_hex):
    """decodescript on a P2TR SPK returns the bech32m address."""
    info = cli(cli_args, "decodescript", spk_hex)
    # Try canonical fields in order of preference.
    for key in ("address", "p2sh_segwit"):
        v = info.get(key) if isinstance(info, dict) else None
        if isinstance(v, str):
            return v
    seg = (info or {}).get("segwit") or {}
    if isinstance(seg, dict) and seg.get("address"):
        return seg["address"]
    raise RuntimeError(f"could not extract address from decodescript: {info}")


def wait_for_tx_in_block(cli_args, txid, timeout_s=900):
    """Poll until getrawtransaction(txid, true) shows confirmations >= 1."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            tx = cli(cli_args, "getrawtransaction", txid, "true")
            if tx and isinstance(tx, dict) and tx.get("confirmations", 0) >= 1:
                return tx
        except RuntimeError:
            pass
        time.sleep(15)
    raise TimeoutError(f"timeout waiting for {txid} to confirm")


def find_vout_for_spk(tx, spk_hex):
    """Walk a decoded TX's outputs and return the index whose SPK matches."""
    for i, v in enumerate(tx.get("vout", [])):
        if v.get("scriptPubKey", {}).get("hex") == spk_hex:
            return i
    raise RuntimeError(f"no output in tx {tx.get('txid')} has SPK {spk_hex}")


def build_cpfp_child(cli_args, dist_txid, anchor_vout, anchor_sats,
                     lsp_change_address, package_fee_sats):
    """Build a CPFP child: anchor input + wallet fee input → LSP change.

    Uses bitcoin-cli's wallet for fee selection and signing.
    """
    # 1. Base TX: anchor input + placeholder output equal to the anchor sats,
    #    going to the LSP change address.  Bitcoin Core's createrawtransaction
    #    rejects empty outputs (error -8 "TX must have at least one output"),
    #    so we seed one and let fundrawtransaction add a wallet fee input and
    #    a real wallet change output alongside.
    base_hex = cli(cli_args, "createrawtransaction",
                   [{"txid": dist_txid, "vout": anchor_vout,
                     "sequence": 0xFFFFFFFE}],
                   [{lsp_change_address: f"{anchor_sats / 1e8:.8f}"}])

    # 2. Have the wallet add a fee input + change output.  Tell it the
    #    P2A anchor's weight so it doesn't undershoot the fee.
    #    P2A anchor weight: 41 bytes prevout/script/seq * 4 + 1 wu witness = 165 wu.
    fund_opts = {
        "changeAddress": lsp_change_address,
        "input_weights": [{
            "txid": dist_txid, "vout": anchor_vout, "weight": 165
        }],
        # Force a flat fee — caller picked package_fee_sats already.
        # `fee_rate` is sat/vB in Bitcoin Core 25+.
        "fee_rate": max(2, package_fee_sats // 200),
    }
    funded = cli(cli_args, "fundrawtransaction", base_hex, fund_opts)
    funded_hex = funded["hex"]

    # 3. Sign wallet inputs.  Provide prevtxs for the P2A anchor so the
    #    wallet doesn't refuse to sign on an unknown input.
    prevtxs = [{
        "txid": dist_txid,
        "vout": anchor_vout,
        "scriptPubKey": "51024e73",       # P2A: OP_1 OP_PUSHBYTES_2 0x4e73
        "amount": anchor_sats / 1e8,
    }]
    signed = cli(cli_args, "signrawtransactionwithwallet", funded_hex, prevtxs)
    # The anchor input has no signature (anyone-can-spend); some Bitcoin
    # Core versions still report complete=true, others complete=false.
    # Trust the hex either way and let submitpackage adjudicate.
    return signed["hex"]


def main():
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    ap.add_argument("--users", type=int, required=True)
    ap.add_argument("--slot-deposit-sats", type=int, required=True)
    ap.add_argument("--funding-height", type=int, default=0)
    ap.add_argument("--recovery-blocks", type=int, default=0)
    ap.add_argument("--seed-base", type=lambda x: int(x, 0), default=0xB1)
    ap.add_argument("--build-tool", default="./build/ctv_factory_build",
                    help="path to compiled ctv_factory_build binary")
    ap.add_argument("--bitcoin-cli", default="bitcoin-cli",
                    help="bitcoin-cli command, e.g. 'bitcoin-cli -signet ...'")
    ap.add_argument("--lsp-change-address", required=True,
                    help="LSP-owned address to receive CPFP child's change")
    ap.add_argument("--package-fee-sats", type=int, default=2000)
    ap.add_argument("--no-broadcast", action="store_true",
                    help="build everything but skip sendtoaddress/submitpackage")
    args = ap.parse_args()

    cli_args = args.bitcoin_cli.split()

    # --- 1. Build factory in-memory --------------------------------------
    print(f"[1/8] building factory: users={args.users} "
          f"deposit={args.slot_deposit_sats}sat")
    build_args = [
        "--users", str(args.users),
        "--slot-deposit", str(args.slot_deposit_sats),
        "--funding-height", str(args.funding_height),
        "--recovery-blocks", str(args.recovery_blocks),
        "--user-seed-base", str(args.seed_base),
    ]
    f = run_build_tool(args.build_tool, build_args)
    funding_spk = f["funding_spk_hex"]
    total_funding = int(f["total_funding_sats"])
    anchor_vout = int(f["anchor_vout"])
    anchor_sats = int(f["anchor_sats"])
    print(f"      funding_spk_hex   = {funding_spk}")
    print(f"      total_funding     = {total_funding} sat")

    # --- 2. Derive bech32m address ----------------------------------------
    print(f"[2/8] decoding funding address ...")
    funding_address = decode_spk_to_address(cli_args, funding_spk)
    print(f"      funding_address   = {funding_address}")

    if args.no_broadcast:
        print("--no-broadcast set; stopping after address derivation")
        return

    # --- 3. Fund the factory ----------------------------------------------
    print(f"[3/8] sending {total_funding} sat → {funding_address}")
    btc = f"{total_funding / 1e8:.8f}"
    funding_txid = cli(cli_args, "sendtoaddress", funding_address, btc)
    print(f"      funding_txid      = {funding_txid}")

    # --- 4. Wait for confirmation, find vout ------------------------------
    print(f"[4/8] waiting for funding TX to confirm "
          f"(~30s on Mutinynet, ~10min on signet)...")
    tx = wait_for_tx_in_block(cli_args, funding_txid)
    funding_vout = find_vout_for_spk(tx, funding_spk)
    print(f"      funding_vout      = {funding_vout}")

    # --- 5. Build segwit dist TX with witness -----------------------------
    print(f"[5/8] building segwit dist TX with CTV-path witness ...")
    f2 = run_build_tool(args.build_tool, build_args + [
        "--funding-txid", funding_txid,
        "--funding-vout", str(funding_vout),
    ])
    dist_tx_hex = f2["dist_tx_segwit_hex"]
    print(f"      dist_tx_bytes     = {f2['dist_tx_segwit_bytes']}")
    decoded = cli(cli_args, "decoderawtransaction", dist_tx_hex)
    dist_txid = decoded["txid"]
    print(f"      dist_txid         = {dist_txid}")

    # --- 6. Build CPFP child ----------------------------------------------
    print(f"[6/8] building CPFP child (anchor + wallet fee → change) ...")
    cpfp_hex = build_cpfp_child(cli_args, dist_txid, anchor_vout,
                                 anchor_sats, args.lsp_change_address,
                                 args.package_fee_sats)
    print(f"      cpfp_child_bytes  = {len(cpfp_hex) // 2}")

    # --- 7. submitpackage [dist_tx, cpfp_child] ---------------------------
    print(f"[7/8] submitpackage [dist_tx, cpfp_child] ...")
    try:
        result = cli(cli_args, "submitpackage", [dist_tx_hex, cpfp_hex])
        print(f"      result            = {json.dumps(result, indent=2)}")
    except RuntimeError as e:
        sys.stderr.write(f"submitpackage failed: {e}\n")
        sys.stderr.write("If this is a policy rejection on V2 parent + ephemeral\n"
                         "anchor, the C library may need a V3/TRUC mode added.\n")
        sys.exit(1)

    # --- 8. Wait for dist TX to confirm -----------------------------------
    print(f"[8/8] waiting for dist TX to confirm ...")
    wait_for_tx_in_block(cli_args, dist_txid)
    print(f"DONE — {args.users} user UTXOs materialized.")
    print(f"      dist_txid         = {dist_txid}")
    print(f"      inspect on the explorer to see all user outputs.")


if __name__ == "__main__":
    main()
