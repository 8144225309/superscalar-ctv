# CTV Channel Factory — v0 strawman design

**Status:** STRAWMAN v0 — not the final design, intentionally exposes open
questions for review
**Fork:** superscalar-ctv (default branch `ctv-covenant-utxo-sharing`)
**Feature:** #2 of the CTV arc (covenant construction). Builds on feature #1
(detection, `docs/ctv-detection-design.md`, shipped in #1).
**Author:** v0 review pass — please redline; second pass becomes the real
design doc.

---

## 0. Why a strawman first

Three things were unclear before this pass:

1. Whether the existing SuperScalar codebase has the right primitives to bolt
   CTV on, or needs a re-architecture (verdict: it already has them).
2. Whether plain CTV is enough or we need LNHANCE / APO (verdict: plain CTV
   is sufficient for the entire 6-feature roadmap; APO is a future
   enhancement for updateable templates, LNHANCE is irrelevant to the
   factory layer).
3. The exact BIP-119 template-hash serialization and the script byte layout
   to commit to (now nailed down — see §6).

Writing the strawman crystallizes what we *still* don't know (collected in
§14) so research from here on is targeted, not exploratory.

## 1. TL;DR

Add a single Taproot **script-path leaf** to the funding output. The leaf is
the canonical 34-byte CTV pattern `<TH> OP_CHECKTEMPLATEVERIFY`, where TH is
the BIP-119 template hash of the **already-existing distribution TX** that
SuperScalar builds at factory creation.

- **No protocol re-architecture.** All current MuSig2/DW/channel/watchtower
  machinery stays. The CTV leaf is an alternate spending path on the same
  funding output.
- **Unilateral exit becomes one TX, no timelock.** Anyone broadcasts a
  package of `{0-fee distribution TX, CPFP child paying via P2A anchor}`
  and the factory settles in one block. The 6-TX DW chain remains as a
  fallback if mempool policy ever blocks the CTV path.
- **No new opcodes beyond BIP-119.** Mainnet-shippable when CTV activates
  (~May 2027 minimum per the activation client). Mutinynet today.
- **Closes an existing audit gap.** Clients currently *don't* verify the
  distribution TX matches expectations before signing the funding TX
  (documented at `src/client.c:1619-1630`). Under CTV that verification is
  consensus-enforced: an LSP that tries to swap the distribution TX
  produces a funding output whose script-path is unsatisfiable for the
  intended TX.

## 2. Scope

**In scope (this strawman):**
- The funding output's CTV script-path leaf
- Distribution TX format for the CTV path (0-fee parent + P2A anchor)
- Template-hash computation + mandatory client-side verification
- Construction + exit flows
- A 2-layer recursive-nesting sketch for feature #4

**Out of scope (deferred to future docs):**
- LSP-funded factory variant (Timeout Trees-style) — useful for scaling
  past N≈128 but a different value prop; revisit after the bilateral
  version ships
- APO-based template rebinding (BIP-118) for updateable templates — listed
  in §13 as a future variant
- LN-Symmetry / Eltoo at the channel leaves (LNHANCE territory)
- Wire-protocol changes beyond what falls out of §7
- Dashboard / observability — separate follow-up

**Explicitly deferred decisions** (collected in §14):
- Exact mempool-policy behavior of 1P1C package relay across the real
  mainnet relay graph (Track G)
- Recursive-nesting depth/branching arithmetic at the actual dust frontier
  (Track F)
- Whether the strawman's "single-shot, no rebalancing" choice survives
  contact with the UX requirements (the keystone decision in §13)

## 3. Status quo recap

What already exists in the codebase (verified from the audit pass; locations
relative to `C:\pirq\superscalar-ctv`):

| Piece | File:lines | Note |
|---|---|---|
| Single Taproot output builder accepting internal key + optional merkle root | `src/factory.c:99-118` (`build_musig_p2tr_spk`) | Already used everywhere — the natural insertion point |
| Pattern: P2TR with N-of-N key path + script-path leaf | `src/factory.c:186-201` (DW state TXs use `or(N-of-N, CLTV)`) | We're adding a third pattern: `or(N-of-N, CTV)` |
| Distribution TX construction (unsigned) | `src/factory.c:3518-3580` (`factory_build_distribution_tx_unsigned`) | nVersion=2, single input, nSequence=0xFFFFFFFE, nLockTime = factory CLTV timeout |
| Per-client balanced output computation | `src/factory.c:3596-3720` | `budget = funding_amount − fee_sats`, equal split, remainder to last client |
| Conditional P2A anchor | `src/factory.c:3534-3541` + `src/fee.c:90-97` (`fee_should_use_anchor`) | Triggered when urgent fee rate ≥ 1000 sat/kvB; cost subtracted from *first client's* output (this is wrong for the CTV path — see §5) |
| MuSig2 N-of-N keyagg, deterministic order | `src/musig.c:17-36`, `src/factory.c:353-356` | LSP = index 0, clients = 1..N. Byte-identical funding SPK across all parties |
| Distribution TX wire transmission | `src/lsp.c:1139-1160` (LSP sends signed dist TX in `FACTORY_READY`); `src/client.c:796-810` (client receives + stores) | Both sides reconstruct unsigned identically |
| Funding SPK construction site | **NOT FOUND** in the audit pass | The SPK is *passed into* `factory_set_funding` at `src/factory.c:894-907`; the upstream computation site couldn't be located. Likely tooling-side or pre-existing offline flow. This is a gap we need to either find or claim. |

Observations that matter:
- The factory's distribution TX **excludes the LSP from outputs** — only
  clients 1..N receive (`src/factory.c:3528-3541`). The LSP's recourse on
  unilateral exit is via channel-level mechanics. We preserve this on the
  CTV path; the LSP signing the CTV-augmented funding output is rational
  because they earn from cooperative use of the factory and the CTV escape
  is a safety net for users.
- The dist TX is **MuSig2-signed today** for the cooperative-expiry case.
  Under CTV, MuSig2-signing the dist TX is **no longer required** — the
  CTV leaf authorizes any broadcast of the matching template, no signature
  needed. The MuSig2 ceremony for the dist TX can be removed on the CTV
  path (kept for the legacy nLockTime-expiry path).
- The codebase already has a "client verifies funding contribution"
  scaffold marked "optional" in the audit comment. Under CTV that scaffold
  becomes **mandatory** because the security argument depends on it.

## 4. Funding output design

The funding output is a **P2TR** (segwit v1) with:

- **Internal key:** `MuSig2_keyagg(LSP_pk, client_1_pk, …, client_N_pk)`
  — unchanged from today; same deterministic ordering (`src/factory.c:353-356`).
  Tweaked by the script-tree root.
- **Tap leaves (single leaf in v0):**

  ```
  leaf_version = 0xc0                        (1 byte)
  script       = <TH> OP_CHECKTEMPLATEVERIFY (34 bytes)
                = 0x20 || TH(32) || 0xb3
  ```

The tap-tree merkle root is the standard single-leaf tagged hash:
```
tap_leaf_hash = TaggedHash("TapLeaf", 0xc0 || compact_size(34) || 0x20 || TH || 0xb3)
merkle_root   = tap_leaf_hash    (single leaf — no sibling)
```

The funding scriptPubKey is then the standard P2TR (`OP_1 <32-byte tweaked-key>`),
34 bytes total — indistinguishable on-chain from any other P2TR.

**Why a single leaf?** v0 deliberately ships the minimum. If we later want a
side-channel CLTV-expiry path on the script side (matching the existing dist
TX's nLockTime semantics), we add a second leaf. For v0 the CLTV-expiry case
goes through the cooperative key-path spend, which the existing protocol
already handles.

**Spending paths:**

| Path | Witness | Used for |
|---|---|---|
| Key path (MuSig2 N-of-N cooperative) | 64-byte Schnorr sig over BIP-341 sighash | All cooperative operations (rebalance, close, route to a new funding TX) — unchanged from today |
| Script path (CTV leaf) | `[script (34 bytes), control_block (33 bytes)]` — no stack args | Unilateral exit: anyone (no signatures) broadcasts the matching distribution TX |

The control block for the single-leaf case is exactly 33 bytes:
`0xc0 | parity_bit` (1 byte) `|| internal_pubkey_xonly` (32 bytes). No merkle
path required (single leaf).

**Witness footprint of a CTV script-path spend:** ~67 wu = ~17 vbytes.
Adds about 1–2 vbytes per dist TX vs. the cooperative path.

## 5. Distribution TX design

The distribution TX is the **same TX** SuperScalar already builds, with two
adjustments for the CTV path:

### 5.1 Fields

| Field | Value | Source |
|---|---|---|
| nVersion | 2 | unchanged, `tx_builder.c:77` |
| input count | 1 (spends funding TX output 0) | unchanged |
| input.prevout | `funding_txid:0` | unchanged |
| input.nSequence | `0xFFFFFFFE` (final, RBF off) | unchanged, `tx_builder.c:82` |
| input.scriptSig | empty (segwit) | unchanged |
| input.witness | `[CTV leaf script, control block]` for CTV path | **new** |
| output count | N + 1 (clients + P2A anchor) | adjusted (see 5.2) |
| outputs[0..N-1] | per-client P2TR, key-path-only | unchanged in structure |
| outputs[N] | P2A anchor, 240 sat | **must be unconditionally present** in the CTV-path TX (see 5.2) |
| nLockTime | factory CLTV timeout | preserved |

### 5.2 The 0-fee + P2A anchor change

Today the anchor is **conditional** on `fee_should_use_anchor()` returning
true (urgent rate ≥ 1000 sat/kvB) and the anchor cost is **subtracted from
the first client's output** (`src/factory.c:3534-3541`). Two problems for
the CTV path:

1. **Conditional anchor breaks the CTV commitment.** TH is computed from a
   specific outputs list. If we sometimes include the anchor and sometimes
   don't, we'd have two possible TXs but only one TH, and one of them would
   be unbroadcastable. **Fix: the CTV-path dist TX always includes the P2A
   anchor.**
2. **0-fee requirement (BIP-433).** Ephemeral dust is only relayed if the
   parent is **strictly zero fee** — see `bitcoin/bitcoin#31938`. The
   current builder subtracts anchor cost from output[0]; that's still
   "extracting" fee from the spendable amount but the *parent fee* on
   the wire is what matters. Need to verify our current behavior aligns.

   **Fix proposal:** for the CTV path, the dist TX builder produces:
   - per-client output = `budget_per_client` (no anchor cost subtracted from a *client*)
   - LSP residual handling — see §5.3
   - P2A anchor at 240 sat
   - explicit parent fee = `funding_amount − sum(outputs) = 0`

### 5.3 The LSP residual

Today the LSP receives nothing on the distribution TX path (`src/factory.c:3528-3541`).
For the CTV-path TX, the anchor budget has to come from somewhere; the cleanest
allocation is:
- Funding amount = sum of per-client balances + 240 sat (anchor) + 0
- LSP gets 0 from the distribution TX (same as today)
- LSP pays the 240 sat anchor implicitly by sourcing it from the funding (i.e.,
  every funding round commits +240 sat from LSP for the eventual anchor)

This is a small economic ask of the LSP (240 sat ≈ negligible) and keeps the
client outputs full-amount.

**Alternative:** anchor cost subtracted from the *last* client output (so the
first client isn't penalized differently than the others). Bikeshed; pick one
in v1.

### 5.4 CPFP child (the broadcaster's responsibility)

The CTV leaf does not commit to *who* broadcasts. Whoever fires the escape
constructs the child TX:

- Spends `dist_tx:N` (the P2A anchor output)
- Spends one or more of their own UTXOs to provide fee inputs
- Has at least one output covering the package fee at the broadcaster's
  desired feerate
- Broadcasts as a 1P1C package via `submitpackage` RPC (Core 28.0+)

The broadcaster pays the entire package fee for the factory's exit; in
return they get exit guarantees for *all* participants without cooperation.
This is the same economic model as Lightning anchor channels.

**Future:** for users who lack on-chain UTXOs at exit time, the strawman
defers to §14 (open question: per-user anchor outputs, LSP-assisted fee
bumping, etc.).

## 6. CTV template hash computation

Per BIP-119 (now confirmed verbatim from the spec):

```
TH = sha256(
       LE32(nVersion) ||
       LE32(nLockTime) ||
       [ sha256(scriptSigs) if any input has a non-empty scriptSig ] ||
       LE32(input_count) ||
       sha256(concat(LE32(nSequence_i) for each input i)) ||
       LE32(output_count) ||
       sha256(concat(serialize(output_j) for each output j)) ||
       LE32(input_index)
     )
```

For our distribution TX:
- All scriptSigs are empty (segwit input) → **the `scriptSigs` field is elided**
- `input_count = 1`
- `nSequence = 0xFFFFFFFE` (single input)
- `output_count = N + 1` (clients + P2A anchor)
- `input_index = 0` (the only input)

So the computation reduces to:
```
sequences_hash = sha256(LE32(0xFFFFFFFE))
outputs_hash   = sha256( concat(serialize(out_j)) for j in 0..N )
TH             = sha256(
                   LE32(2)         ||   // nVersion
                   LE32(cltv)      ||   // nLockTime
                   LE32(1)         ||   // input_count
                   sequences_hash  ||
                   LE32(N+1)       ||   // output_count
                   outputs_hash    ||
                   LE32(0)              // input_index
                 )
```

Both LSP and every client compute this independently from the agreed
parameters (per-client balances, CLTV timeout, anchor inclusion). Determinism
across parties depends on:
- Deterministic per-client output amount (existing equal-split logic)
- Deterministic output *order* (the current code uses client index order;
  preserve that)
- Deterministic P2A inclusion (CTV path → always include)

If any of those drift between parties, TH drifts, and the script-path spend
fails. Section 8 specifies the verification protocol that forces alignment.

### 6.1 The frozen-funds risk (BIP-119 spec note)

> "Suppose one creates a template address which forwards 1 BTC to cold
> storage. Creating an output to this address with less than 1 BTC will be
> frozen permanently."

The template doesn't commit to the **input amount**. If our funding TX
deposits less than the committed-distribution total, the funds are
unspendable via CTV (the dist TX is invalid because its outputs exceed
inputs). The cooperative MuSig2 path remains, so funds aren't *permanently*
frozen — but the unilateral exit is broken.

**Mitigation:** the funding TX construction code must verify the input
amount matches `sum(committed_outputs) + 0` (i.e., exactly the budget the
distribution TX consumes). Add an explicit assertion in the funding builder.

## 7. Construction flow

The CTV path inserts itself into the existing factory-construction sequence
without new round trips:

```
LSP                                            Client (each, in parallel)
 │                                              │
 │ ── FACTORY_PROPOSE (params, balances) ────►  │
 │                                              │
 │                                              │   compute:
 │                                              │     dist_tx = build_dist_tx_ctv(params)
 │                                              │     TH      = ctv_template_hash(dist_tx)
 │                                              │     keyagg  = musig_keyagg(all_pks)
 │                                              │     spk     = p2tr(keyagg, ctv_leaf(TH))
 │                                              │     verify: spk matches LSP's claimed spk
 │                                              │     verify: my balance is at outputs[my_idx]
 │                                              │
 │ ◄── FACTORY_PROPOSE_ACK + MuSig2 round-1 ─── │
 │       (nonces over the funding-TX sighash)   │
 │                                              │
 │ ── MuSig2 round-2 / partials ────────────►   │
 │                                              │
 │ ── FACTORY_READY (signed funding-TX hex) ─►  │
 │     + signed pre-images for DW fallback      │
 │                                              │
 │   ┌──────────────────────────────────────┐   │
 │   │ Note: the dist TX is NOT MuSig2-     │   │
 │   │ signed on the CTV path. Its broadcast│   │
 │   │ authority comes from the funding     │   │
 │   │ output's CTV leaf, not a signature.  │   │
 │   └──────────────────────────────────────┘   │
 │                                              │
 │ ── FUNDING_BROADCAST (txid) ──────────────►  │
 │                                              │
 ▼                                              ▼
 Factory live
```

**Net wire delta vs today:** none. `FACTORY_PROPOSE` already carries the
parameters needed to derive the dist TX; the CTV path adds **client-side
computations**, not new messages. The existing `FACTORY_READY` still
ships the signed funding TX. The only thing it stops shipping is the
*signed* distribution TX (now unsigned — or the field becomes "for legacy
cooperative-expiry path, unused under CTV mode").

## 8. Client-side verification (mandatory under CTV)

This is the section that closes the audit gap at `src/client.c:1619-1630`.

Before each client signs its share of the funding TX MuSig2, it MUST:

1. **Reconstruct the unsigned distribution TX** from the factory parameters
   in `FACTORY_PROPOSE`. Use the existing
   `factory_build_distribution_tx_unsigned(...)` helper.
2. **Locate its own output** in the dist TX (`outputs[my_client_idx]`).
3. **Verify** the output script is its own P2TR key, and the amount matches
   `expected_balance − maybe(anchor_share)` — within tolerance for the
   rounding the equal-split logic produces.
4. **Verify the P2A anchor** is present at the documented index, with the
   documented value (240 sat) and script (`OP_1 0x02 0x4e73`).
5. **Compute** `TH = ctv_template_hash(dist_tx)`.
6. **Reconstruct** the funding SPK independently:
   `expected_spk = p2tr(keyagg(all_pks), single_leaf(<TH> OP_CTV))`.
7. **Verify** the LSP's funding-TX output 0 script equals `expected_spk`.
8. Only then participate in MuSig2 round-1.

If any check fails, the client aborts the ceremony. This is the security
contract: **a misbehaving LSP can't construct a funding output whose CTV
leaf would settle to a TX other than the one every client independently
computed.**

The existing `src/musig.c` keyagg-ordering guarantee (LSP=0, clients=1..N)
means every party arrives at byte-identical SPK and TH if and only if they
agree on the parameters. There is no room for the LSP to "swap" the dist
TX after-the-fact.

## 9. Exit flows

### 9.1 Unilateral exit (the new default)

Any single participant — client *or* LSP — can:

1. Retrieve the dist TX template (recompute from persisted params, or
   load from `persist_load_distribution_tx` — `src/persist.c:6634-6691`).
2. Construct the script-path witness:
   `witness = [ ctv_leaf_script (34 bytes), control_block (33 bytes) ]`
3. Construct a CPFP child TX spending the P2A anchor + own UTXOs for fees.
4. Broadcast as a 1P1C package: `bitcoin-cli submitpackage [dist_tx_hex, child_hex]`.

Both confirm together (or none confirm, the broadcaster's UTXOs return to
them). On confirmation, every client has their P2TR UTXO at their key. The
factory is dissolved.

### 9.2 Cooperative exit (unchanged)

MuSig2 N-of-N key-path spend of the funding output. Today's
`lsp_run_factory_close` path is unchanged.

### 9.3 DW fallback (retained safety net)

If mempool policy ever rejects the CTV path (relay misconfiguration, anchor
output spec drift, etc.), the existing pre-signed DW tree remains
broadcastable. Operationally a degraded path (6 TXs, days on mainnet) but
guaranteed available. Keep all current DW signing + persistence machinery.

### 9.4 nLockTime-expiry path

Today the dist TX is also broadcast at expiry of the factory CLTV. Under
CTV, the same TX can be broadcast at any time (no nLockTime wait needed for
script-path satisfaction) — but if the broadcaster waits until expiry, the
nLockTime is satisfied and the broadcast works the same way it does today,
just via CTV authorization instead of MuSig2 signature.

## 10. Failure modes / attacker capability surface

| Attack | Before CTV (MuSig2 only) | After CTV |
|---|---|---|
| LSP equivocates on distribution (signs two conflicting dist TXs) | possible; mitigated by poison-TX defense (heavy machinery) | **impossible** — only one TH commits, only one TX satisfies the script |
| LSP equivocates on channel state | possible; mitigated by watchtower / penalty | unchanged — channel layer still uses today's defenses |
| LSP refuses to broadcast funding TX | possible; aborts the factory | unchanged |
| LSP refuses cooperative updates | possible; clients exit unilaterally | **easier to exit** — one TX instead of six over days |
| Client broadcasts dist TX maliciously | impossible (no signature held) | possible — but the TX pays everyone their committed balance anyway; not an attack, just an early settlement |
| Anyone (third party) broadcasts dist TX | impossible | possible (the CTV leaf is permissionless) — but they have to pay the package fee; settles factory cleanly. **Not an attack.** |
| Malicious participant constructs alternative dist TX | possible to *propose* but never had spending authority; today caught by ceremony abort | **caught at verification step §8** — the funding SPK they'd produce wouldn't match what the rest of the parties computed |
| LSP swaps dist TX between propose and broadcast | possible if clients skip verification (audit gap) | **impossible** — clients verify SPK matches TH(dist_tx) before signing funding |
| Mempool censorship of the dist TX | n/a (signed TX is private until broadcast) | possible in theory — mitigation: DW fallback (§9.3); long-term: relay diversity, but BIP-433 1P1C policy is now standard |

**Net assessment:** the new attacker surface is narrower than the old one.
The "equivocation on distribution" class is eliminated by consensus
enforcement. The remaining attacks (stall, channel-state) are unchanged
and have unchanged defenses. We can **simplify** the factory-layer poison-TX
machinery on the CTV path (channel-layer poison TX stays — it's defending
against a different attack).

## 11. Recursive sub-factory nesting (feature #4 sketch)

CTV is non-recursive by design — a single CTV invocation commits to a single
TX. But the committed TX can itself contain CTV outputs, so a *hierarchy* of
templates can be baked at funding time.

### 11.1 Topology

Two-layer example, N = 128 users, fan-out K × M = 16 × 8:

```
                  ROOT FUNDING UTXO
                  P2TR with CTV leaf → TX_root_dist
                          │
                          ▼ (broadcast TX_root_dist)
            ┌─────────────┼─────────────┐
            │             │             │
       sub_0 P2TR    sub_1 P2TR  …  sub_15 P2TR    P2A anchor
       (CTV→sub_0_dist)
            │
            ▼ (broadcast sub_0_dist)
       ┌────┴────┐
       │    …    │
     user_0   user_7   P2A anchor
```

- 1 on-chain funding UTXO commits the whole 128-user structure.
- Layer-1 dist TX (`TX_root_dist`): 16 sub-factory P2TR outputs + P2A anchor.
- Each layer-2 dist TX (`sub_i_dist`): 8 user P2TR outputs + P2A anchor.
- All TXs' templates are computed at funding time and the corresponding TH
  values committed into the tree of CTV leaves.

### 11.2 Per-exit cost (sparse exit case)

To exit *one* user, the broadcaster fires:
- `TX_root_dist` (~770 vbytes for 16 outputs + anchor) + its CPFP child
- `sub_i_dist` (~426 vbytes for 8 outputs + anchor) + its CPFP child

Approximate vbytes for the two parent TXs: ~1200 vbytes. At 10 sat/vB,
about 12k sat to exit. Per-user.

### 11.3 vbyte budget at scale

Per the BIP-119 outputs-hash + our P2TR structure (43 vbytes per output,
~82 vbytes overhead):

| Layer size | Dist TX vbytes (approx) | Notes |
|---|---|---|
| 4 outputs + anchor | ~254 | tiny |
| 8 outputs + anchor | ~426 | |
| 16 outputs + anchor | ~770 | |
| 32 outputs + anchor | ~1,458 | |
| 64 outputs + anchor | ~2,930 | |
| 128 outputs + anchor | ~5,586 | |

**Trade-off:** sparse exits favor deep narrow trees (one user out = two
small TXs), bulk exits favor flat wide trees (all-users out = one big TX).
The factory operator picks the topology at funding time based on expected
exit patterns.

### 11.4 Hierarchical verification

A client at depth-2 leaf must verify:
- The root funding output's CTV leaf has TH = hash(`TX_root_dist`)
- `TX_root_dist`'s output[i] (their sub-factory) is a P2TR with CTV leaf
  TH = hash(`sub_i_dist`)
- `sub_i_dist`'s output[j] (their position) is their P2TR at the expected
  amount

Cost: O(depth) verification per client, where depth is bounded by economic
limits in §11.3.

### 11.5 The bilateral-vs-LSP-funded question

For N > ~128 in a single root UTXO, the MuSig2 ceremony on funding becomes
impractical (everyone must be online; signing cost grows). Two paths past
that:

- **LSP-funded variant (Timeout Trees-style):** LSP funds the root UTXO
  alone; no MuSig2 ceremony at funding. Trade-off: LSP holds the funds
  until the dist TX broadcasts; users have no on-chain contribution
  proof. Each layer's CTV leaf has an LSP-CSV-timeout fallback so the
  LSP can recover unused capacity.
- **Bilateral (v0 strawman):** every participant contributes; MuSig2 N-of-N;
  bounded by ceremony scaling. Targets N ≤ 128 in one UTXO, with depth
  extending the *total* user count without raising ceremony N.

Strawman picks **bilateral** to match the existing SuperScalar value prop.
LSP-funded is a Timeout Trees adaptation — separate doc.

## 12. Update-semantics decision (the keystone)

CTV alone fixes the distribution template at funding time. Three options:

| Option | What it means | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A. Single-shot** | Factory is funded once; balances fixed; exit pays funding-time split | simple; ships first; CTV alone | no in-factory rebalancing | **strawman picks this** |
| B. Cooperative re-fund | Each rebalance is a new funding TX with a fresh CTV; old funding's CTV remains a stale escape until new confirms | works with CTV alone; bounded staleness | every rebalance = on-chain TX | future variant |
| C. APO rebinding | BIP-118 SIGHASH_ANYPREVOUT lets a dist-TX signature rebind to a new funding output, no re-fund needed | cleanest UX | needs APO active; mainnet timeline TBD | Mutinynet experiment (Inquisition has APO) |

**Strawman picks A** because:
1. It's enough for the README's stated value prop ("one-TX exit faster
   than the DW tree").
2. Mainnet activation is CTV-only on the visible horizon (~May 2027 for
   CTV; APO is a separate process).
3. A and C are not mutually exclusive — you can ship A on mainnet now
   (when CTV activates) and add C later as an opt-in mode that requires
   the APO node feature.
4. Channels at the leaves still rebalance via standard LN routing. The
   "no rebalancing" refers to *factory-level balances*, not channel-state
   updates inside each channel.

This decision is the most likely to be revisited. The strawman exposes it
explicitly so it can be redlined.

## 13. Integration map

### 13.1 What stays unchanged

- MuSig2 N-of-N ceremony for funding-output cooperative spends
  (`src/musig.c`, ceremony state machine in `src/lsp.c`/`src/client.c`)
- Decker-Wattenhofer pre-signed tree (kept as fallback per §9.3)
- Channel-level: commitments, HTLCs, PTLCs, channel close, watchtower
  duties (defending against channel-state breaches, not factory breaches)
- `factory_compute_distribution_outputs_balanced` per-client math
- Distribution TX persistence (`persist_save/load_distribution_tx`)
- Wire-protocol message set

### 13.2 What changes

- The funding output's scriptPubKey now includes a tap leaf (was key-path-only)
- The distribution TX builder grows a `--ctv-path` mode:
  - Anchor is unconditional (was conditional)
  - Anchor cost allocation: either uniform-LSP-pays or last-client-pays
    (pick one — see §5.3)
  - Parent fee is strictly 0 (was implicit-via-output-shrinkage)
- The MuSig2 ceremony for the *distribution TX* is no longer performed on
  the CTV path. The dist TX is unsigned; broadcast authority is the CTV
  leaf. (Cooperative-expiry path still uses MuSig2 if anyone wants the
  signed-cooperative-expiry route, but it's now redundant.)
- The factory-layer poison-TX defenses can be **disabled** on the CTV path
  (LSP can no longer equivocate on the distribution). Channel-layer
  poison-TX defenses stay.

### 13.3 What's new

- A funding-SPK construction helper that wraps `build_musig_p2tr_spk` with
  the CTV leaf:
  ```
  build_ctv_funding_spk(pubkeys[], n, dist_tx) → spk[34]
  ```
  This is the missing piece from the audit (the codebase doesn't currently
  expose a clear funding-SPK builder — see §3).
- `ctv_template_hash(unsigned_tx) → TH[32]` per BIP-119 §6.
- The mandatory client-side verification step §8 (was an optional/missing
  scaffold).
- A CTV-path exit driver (constructs the script-path witness, builds a
  CPFP child, calls `submitpackage`).
- Dashboard surface: a "CTV exit available" indicator and the
  one-TX-vs-DW-chain cost projection (already partly there via
  `Chain-broadcast cost` from PR #291).

### 13.4 Operator-visible changes

- Force-close cost on the dashboard becomes the **CTV path cost** by
  default (one-TX + anchor), not the DW chain cost.
- New operator flag (or auto): `--factory-mode=ctv | dw | both`
  (default: `both`, where the CTV path is the unilateral default and DW
  is the kept-around fallback).
- `--ctv-mode` (from feature #1) becomes a hard prerequisite — already
  refuses on a non-CTV node.

## 14. Open decisions and research TODOs

Tagged to the research track that resolves each:

- [Track B] Confirm the `OP_PUSHBYTES_32` (0x20) opcode prefix is the
  correct encoding in tapscript (it is in legacy script; check the
  taproot tapscript encoding spec). Likely fine, but verify.
- [Track F] Concretize the dust frontier: at what (N × M) does any
  per-leaf user output fall below the 546-sat P2TR dust threshold?
  Produce a sizing table.
- [Track F] Sub-dust client policy: round down to 0 (loss), exclude from
  the dist TX (re-allocate to a leftover output), refuse to fund the
  factory if any client would be sub-dust.
- [Track F] Decide the recursive-nesting maximum depth and topology for
  v1 (likely 2 layers, 16×8 or 8×16, supporting 128 users in one root
  UTXO).
- [Track G] Mempool-policy survey: validate the 1P1C package-relay path
  actually propagates across the relay graph at expected rates. Test on
  Mutinynet first.
- [Track G] CPFP child funding: who pays when the broadcasting client
  has no UTXOs at exit time? Options:
  - LSP-assisted (LSP supplies the CPFP child's fee input via a
    cooperative ask)
  - Per-user anchor outputs (every client gets their own anchor in
    the dist TX, can self-CPFP)
  - "Bring your own UTXO" (operator advisory)
- [Track A pass 2] Read Timeout Trees in detail and lift any topology
  ideas worth borrowing (especially the LSP-CSV-timeout sweep pattern,
  which we may want to add as a second tap leaf in v1).
- The §5.3 LSP-anchor allocation: which output absorbs the 240-sat
  anchor cost? Bikeshed.
- Wire-protocol stance: the dist TX is no longer signed on the CTV path
  — should `FACTORY_READY` carry the *unsigned* dist TX (so clients
  can verify a canonical encoding), or just rely on each side computing
  it independently? (Sending it is a one-line change and removes a
  source of "did we compute the same bytes?" bugs.)
- Frozen-funds mitigation (§6.1): add an explicit funding-amount
  assertion to the funding TX builder.
- Decide the §12 keystone: does the strawman's single-shot pick survive
  contact with the product UX team? If not, reconsider Option B
  (cooperative re-fund) as v1.

## 15. Implementation phasing

Each step is its own PR, in this order:

1. **Phase 2a — script primitives**
   - `ctv_template_hash(unsigned_tx)` per §6, with unit tests against the
     known-good Inquisition payload (we already have one from the live
     two-node test).
   - `build_ctv_leaf_script(TH) → 34 bytes` + `build_ctv_funding_spk`.
   - Standalone unit tests; no wire changes.

2. **Phase 2b — distribution TX, CTV-path variant**
   - 0-fee + unconditional-anchor builder.
   - Test that vanilla MuSig2-path dist TX is byte-identical to today.

3. **Phase 2c — client verification (§8)**
   - Implement the mandatory verification step.
   - This closes the audit gap independently and can ship even without
     CTV being enabled (the verification just verifies the existing
     MuSig2 dist TX matches expectations).

4. **Phase 3 — exit flow**
   - CTV-path exit driver: construct script-path witness + CPFP child +
     `submitpackage`.
   - Live-network test: extend `tools/test_ctv_node_detection.sh` to
     actually fire a CTV escape on the Inquisition node (we already
     proved the LSP proceeds; now broadcast).

5. **Phase 4 — recursive nesting (depth 2)**
   - 2-layer hierarchical CTV construction.
   - Hierarchical client verification.
   - Dust math + topology selector.

6. **Phase 5 — client-side detection + verification**
   - Extend feature #1 to client side.
   - Verify CTV node before accepting a `FACTORY_PROPOSE` from an LSP.

7. **Phase 6 — Mutinynet end-to-end campaign**
   - Multi-day Mutinynet run with a real CTV node, multiple factories,
     real exits via the CTV path, real recursive sub-factories.
   - Operator drill on signet.

Mainnet readiness: targets CTV activation (~May 2027 minimum). Until then,
Mutinynet is the test ground; the existing two-node CI test confirms the
LSP correctly refuses anything that isn't CTV-enforcing.

## 16. References

- BIP-119 (CTV) — [spec](https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki)
  · [Optech topic](https://bitcoinops.org/en/topics/op_checktemplateverify/)
  · [Covenants.info](https://covenants.info/proposals/ctv/)
- BIP-433 (Ephemeral dust) — [spec](https://github.com/bitcoin/bips/blob/master/bip-0433.mediawiki)
  · [bitcoin#30239](https://github.com/bitcoin/bitcoin/pull/30239)
  · [Optech: ephemeral anchors](https://bitcoinops.org/en/topics/ephemeral-anchors/)
  · [bitcoin#31938 — 0-fee constraint](https://github.com/bitcoin/bitcoin/issues/31938)
- BIP-118 (ANYPREVOUT) — [spec](https://anyprevout.xyz/) ·
  [Inquisition PR #4](https://github.com/bitcoin-inquisition/bitcoin/pull/4)
- Timeout Trees (John Law) — [Bitcoin Magazine](https://bitcoinmagazine.com/technical/timeout-trees-a-solution-to-scaling-lightning-network-lsps)
- LNHANCE bundle — [bitcoindev post](https://groups.google.com/g/bitcoindev/c/AlMqLbmzxNA)
  · [CTV+CSFS deep dive (HackMD)](https://hackmd.io/@AbdelStark/bitcoin-covenant-toolkit-ctv-csfs)
- SuperScalar feature #1 detection design — `docs/ctv-detection-design.md`
  (this fork, merged in #1)
- Existing distribution-TX code — `src/factory.c:3518-3720`
- Existing Taproot builder — `src/factory.c:99-118`
- Audit gap (client doesn't verify dist TX today) —
  `src/client.c:1619-1630`

---

**Review asks for v1:**

1. Redline §12 — is single-shot acceptable, or do we need APO support before
   shipping?
2. §5.3 — pick the anchor-cost allocation (LSP-pays vs last-client-pays).
3. §11.5 — confirm bilateral-only for v0 (defer LSP-funded variant).
4. Wire-protocol — should `FACTORY_READY` ship the unsigned dist TX for
   verification, or rely on independent reconstruction?
5. Anything missing from the §14 open-questions list.
