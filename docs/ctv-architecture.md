# SuperScalar under CTV — architecture reference

**About this document**

- Architecture-level reference for adapting SuperScalar to `OP_CHECKTEMPLATEVERIFY` (BIP-119). Not an implementation spec — each feature gets its own design doc when it lands.
- Reflects the **LSP-funded** capital model and the **`lsp-takes-all`** economic mode (see §1).
- Tracks two design variants: **CTV-escape mode** (minimal change to today's protocol) and **CTV-committed mode** (replaces the MuSig2 pre-signing ceremony with covenant commitments).
- Open architectural questions are surfaced in §6 rather than hand-waved past.
- Builds on feature 1 (`ctv-detection-design.md`, shipped in #1 — node-capability detection).

---

## 1. Funding model

The protocol — today and in every CTV variant tracked here — is **LSP-funded**:

- The **LSP provides 100% of factory capital**. Clients do not bring sats in.
- Clients receive **inbound liquidity** from the LSP at no upfront cost; they get a routable channel slot.
- The funding-output **MuSig2 N-of-N is about consent to spend**, not capital contribution. Every participant signs to cooperatively close, but only the LSP put coins in.
- The **economic mode is `lsp-takes-all`**: the LSP earns routing fees; clients pay nothing for routing access; there is no profit sharing in this design.

Any alternative model — clients bringing sats in, profit-shared routing fees, cooperative-pool factories — is **out of scope** for this architecture. Those are a separate research thread that has not been nailed down, and they would be an additive design that does not invalidate anything described below.

The distribution TX outputs reflect this: clients receive per-slot amounts; the LSP receives nothing from the dist TX. (The LSP recoups capital over time through routing fee economics, not by claiming an output share at exit.)

## 2. The two variants

Both variants are LSP-funded, `lsp-takes-all`. They differ in **how the spending tree is committed** and therefore in what's required at factory creation time.

| Aspect | CTV-escape mode (minimal) | CTV-committed mode (full) |
|---|---|---|
| Spending tree under the funding output | MuSig2 N-of-N pre-signed (today's DW tree, unchanged) | CTV commits the dissolution TX; no MuSig2 pre-signing of the spending tree |
| MuSig2 ceremony at factory creation | Required (clients online for 2-round signing) | Not required for the spending tree (LSP creates the funding output unilaterally) |
| Practical N per factory | Bounded ~128 by the ceremony coordination cost | Arbitrary — no N-of-N bottleneck at funding time |
| DW invalidation tree | Retained as fallback for unilateral exit | Removed — the CTV escape replaces it |
| Unilateral exit cost | 1 TX (CTV path) or 6 TXs (DW fallback) | 1 TX (CTV is the only path) |
| Code-change scope | Small additive | Substantial redesign |
| Honest framing of the value | "Existing factory + a fast exit path" | "The actual CTV scaling unlock" |

The fork is named after CTV's covenant primitive; **CTV-committed mode is the honest target** of a CTV fork. CTV-escape mode is a defensible stepping stone that ships value sooner with much smaller scope, but doesn't unlock anything CTV is unique for.

## 3. Component-by-component map

What changes (and doesn't) under each variant. Components are listed in roughly the order they appear in a factory's lifecycle.

### 3.1 Funding TX construction (LSP-side)

| Today | CTV-escape | CTV-committed |
|---|---|---|
| LSP spends its own UTXO into the factory funding output (P2TR over MuSig2 keyagg of all participants) | Same, but the P2TR's taptree now contains a CTV leaf | Same; LSP-timeout-sweep leaf may be added so the LSP can reclaim unclaimed slots |

The LSP signs the funding TX itself with its own wallet keys — that is unchanged in both variants and was never an N-of-N operation. The N-of-N is on the *output*, not the input.

Wiring: today the funding SPK is built somewhere upstream of `factory_set_funding` at `src/factory.c:894-907` (the upstream computation site is not currently visible in `src/`; this is itself a small audit item). Either we find it, or we add a clean `build_ctv_funding_spk(...)` helper as part of this work.

### 3.2 Funding output script (Taproot)

| Today | CTV-escape | CTV-committed |
|---|---|---|
| P2TR, internal key = MuSig2 N-of-N keyagg, no script leaves (key-path only) | Same internal key, taptree contains one leaf: `<TH> OP_CHECKTEMPLATEVERIFY` (34 bytes) | Same internal key, taptree contains: the CTV leaf, plus an LSP-CSV-timeout sweep leaf for slots the user never claims |

The Taproot builder already exists and accepts a merkle root (`src/factory.c:99-118`, `build_musig_p2tr_spk`). Adding a leaf is a small wrapping change.

### 3.3 MuSig2 ceremony at factory creation

| Today | CTV-escape | CTV-committed |
|---|---|---|
| All clients + LSP run a 2-round MuSig2 ceremony pre-signing the entire DW spending tree, distribution TX, and channel commits. Clients must be online. | **Unchanged** — the ceremony still pre-signs the DW tree (kept as fallback) and the dist TX | **Replaced** — the spending tree is CTV-committed, not pre-signed. Per-channel 2-of-2 commits are signed lazily, only when each client comes online to activate. |

This is the single most important difference between the two variants. The "all clients online for the ceremony" constraint is the practical cap on factory N today; removing it is the scaling unlock.

### 3.4 DW spending tree (kickoffs, state TXs)

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Pre-signed chain of kickoff + state TXs; BIP-68 nSequence-based invalidation; rooted at the funding output | **Kept** — used as the fallback unilateral-exit path if the CTV escape can't be relayed | **Removed entirely** — the CTV escape is the only unilateral exit; no chain of timelock-gated TXs |

The DW invalidation tree's whole purpose was layered timeout-based unilateral exit. CTV provides instant unilateral exit, making the DW chain redundant under CTV-committed mode. The fallback is retained under CTV-escape mode as a defensive measure (mempool-policy belt-and-braces).

### 3.5 Distribution TX

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Pre-signed by the N-of-N ceremony; nLockTime = factory CLTV timeout; equal-split per client (`src/factory.c:3518-3580`) | Same TX, **plus** a 0-fee + unconditional-P2A-anchor variant for the CTV path. MuSig2 signature retained for the nLockTime-expiry path. | Same TX shape, **only** the CTV-path variant. No MuSig2 signing of the dist TX — broadcast authority comes from the CTV leaf. |

The distribution TX is computed deterministically on both sides today (`src/musig.c:17-36` keyagg-orders LSP=0, clients=1..N; same inputs → same TX bytes). Under CTV that determinism becomes a security requirement, not just a convenience.

**Anchor allocation** (your call from the earlier conversation): each party gets their own 240-sat P2A anchor in the dist TX, funded from their own contribution. N+1 anchors gives N+1 redundant exit-initiation paths.

**0-fee parent**: BIP-433 ephemeral dust requires the parent to be strictly zero-fee. The CTV-path dist TX's outputs must sum to exactly the funding amount minus the anchor budget; nothing left over as inline fee.

### 3.6 Channel commitments at the leaves

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Pre-signed 2-of-2 commits between LSP and each client, sitting at DW tree leaves; signed during the N-of-N ceremony | **Unchanged** — channel commits still pre-signed during the factory-creation ceremony | 2-of-2 commits signed **lazily** per client, when that client comes online to activate their channel. No factory-creation-time signing of channel commits. |

This is where the "channel activation semantics" open question lives for CTV-committed mode — see §6.

### 3.7 Channels in operation (HTLCs, PTLCs, routing)

Unchanged in both variants once channels are active. BOLT #2/4/8/9/11/12, BOLT #8 transport, gossip, PTLC adaptor sigs — all of this is below the factory layer and CTV doesn't touch it.

### 3.8 Sub-factories (k² PS)

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Nested sub-factory structures inside a leaf for in-leaf scaling | **Unchanged** | Naturally subsumed into recursive CTV nesting (depth-≥2 covenant commitments). The k² abstraction collapses into "CTV commits multiple layers deep." |

### 3.9 PS (Pseudo-Spilman) leaves

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Chained channel-commit structure for arity-≥2 leaves; alternative to plain channel commits | **Unchanged** | Probably unchanged — PS is a channel-style construct that lives below the factory's CTV layer |

### 3.10 Cooperative close (key-path spend)

Unchanged in both variants. MuSig2 N-of-N key-path spend of the funding output. Negotiate any cooperative outcome (close, rebalance, route to a new funding). This is what we use whenever everyone is online and cooperating.

### 3.11 Unilateral exit

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Broadcast DW kickoff → wait CSV → broadcast state TX → wait CSV → … (6 TXs, days on mainnet) | **Default: CTV path** — broadcast {0-fee dist TX, CPFP child via P2A anchor} as a 1P1C package, confirms in 1 block. **Fallback: DW chain** (same as today) | **Only: CTV path**. No DW fallback because no DW tree exists. |

The CTV-path broadcaster is any participant (or even any third party who fronts the package fee — it just dissolves the factory cleanly to the committed slots).

### 3.12 Watchtower duties

**Channel-layer (defending against in-channel breaches)** — Unchanged in both variants. Today's per-channel breach detection + penalty broadcast + L-stock burn machinery continues to apply.

**Factory-layer (defending against LSP equivocation on factory state)** — Substantially simplified under both variants:

- Today the LSP could in principle sign two conflicting dist TXs; the poison-TX defense punishes this.
- Under CTV the LSP **cannot** equivocate on the dist TX — the funding output's CTV leaf commits to exactly one template hash, and only the matching TX satisfies the script-path. Equivocation is consensus-prevented.
- Factory-layer poison-TX machinery can therefore be retired or significantly simplified on the CTV path. Channel-layer machinery stays.

### 3.13 Rotation

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Periodic key rotation via a dedicated MuSig2 ceremony | **Unchanged** | **Needs redesign.** Without a recurring N-of-N ceremony, what's the equivalent of rotation? Most likely: rotation = LSP re-funds with a fresh CTV-committed factory and clients claim into it. |

### 3.14 Wire protocol

| Today | CTV-escape | CTV-committed |
|---|---|---|
| `FACTORY_PROPOSE`, MuSig2 round messages, `FACTORY_READY` carrying the signed dist TX | `FACTORY_PROPOSE` ships the **unsigned** dist TX so clients can verify TH against it before signing (closes the audit gap at `src/client.c:1619-1630`); `FACTORY_READY` unchanged | Substantially different — no MuSig2 ceremony rounds at funding. Wire becomes: LSP advertises factory slots, clients claim asynchronously (per-channel 2-of-2 ceremony on activation) |

### 3.15 Client-side verification (mandatory under CTV)

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Verification is **optional and not implemented** (audit note at `src/client.c:1619-1630`) | **Required**: client recomputes TH from the unsigned dist TX in `FACTORY_PROPOSE`, recomputes the funding SPK independently, refuses to sign if mismatch | Same requirement; verification happens at slot-claim time rather than at factory-creation ceremony time |

Under CTV the verification is consensus-enforced — if the LSP tried to swap the dist TX, the funding output's CTV leaf is unsatisfiable for the swapped TX and the script-path spend simply fails. The client-side check exists to abort *before signing*, but the consensus check makes the security argument independent of client diligence.

### 3.16 Persistence schema

| Today | CTV-escape | CTV-committed |
|---|---|---|
| 60+ tables covering factory state, channels, ceremonies, signing rounds, watchtower data | Add CTV-related columns/tables: per-factory TH, CTV script bytes, control block, "ctv-enabled" flag, CTV exit broadcast log | More substantial: drop DW state tracking tables, add CTV commitment hierarchy tracking, slot-activation state |

Migrations are additive and version-gated per the existing pattern.

### 3.17 Dashboard / operator visibility

| Today | CTV-escape | CTV-committed |
|---|---|---|
| Force-close cost projection (DW chain cost), breach detection panels, ceremony tracking | Force-close cost switches to "CTV path: 1 TX + anchor child"; new "CTV exit available" indicator | Simpler dashboard — no DW tree to visualize, no factory-creation ceremony to track. New views for slot-activation status and LSP capital allocation per slot. |

### 3.18 LSP timeout-sweep (new under CTV-committed mode only)

A second tap leaf on the funding output (or on each sub-factory output, recursively): `<expiry_blocks> OP_CSV OP_DROP <LSP_pk> OP_CHECKSIG`. Lets the LSP reclaim slots that users never claim within the timeout. This is the Timeout-Trees pattern. Open: timeout duration UX and what happens to clients who come back after the sweep.

---

## 4. CTV-escape mode in concrete terms

End-to-end flow for the minimal variant.

**Factory creation:**

1. LSP proposes factory parameters (N, per-slot amounts, CLTV timeout). Includes the unsigned dist TX so clients can verify.
2. Each client and the LSP independently compute:
   - The unsigned dist TX (deterministic from parameters)
   - `TH = BIP119_template_hash(dist_tx)`
   - The CTV leaf script: `<TH> OP_CHECKTEMPLATEVERIFY` (34 bytes)
   - The funding SPK: `P2TR(internal_key = MuSig2_keyagg, merkle_root = tap_leaf_hash(CTV leaf))`
3. Each client verifies its own balance is correctly in the dist TX and that the funding SPK matches what the LSP claims. Aborts if mismatch.
4. MuSig2 N-of-N ceremony pre-signs the DW spending tree, the channel commits, and the dist TX. Same as today.
5. LSP broadcasts the funding TX.

**Factory operation:**

- Channels at the leaves operate normally (HTLCs, PTLCs, BOLT-12 invoices, etc.)
- The LSP routes payments, charges routing fees, keeps them (`lsp-takes-all`).
- Periodic state advances via the DW machinery as today.

**Unilateral exit (CTV path — default):**

1. Any party retrieves the dist TX from persistence (or reconstructs it).
2. Builds the script-path witness: `[<CTV leaf script>, <control_block>]`. No signatures needed.
3. Builds a CPFP child TX spending the broadcaster's own P2A anchor + a fee input from their wallet.
4. `submitpackage [dist_tx_hex, child_hex]` (Core 28.0+ 1P1C package relay).
5. Both confirm in one block. Factory dissolves; each client receives their slot amount.

**Unilateral exit (DW fallback):**

If the CTV path is blocked (mempool policy quirk, P2A relay drift), broadcast the existing pre-signed DW tree. Same as today.

**Cooperative close:**

MuSig2 N-of-N key-path spend of the funding output. Unchanged.

## 5. CTV-committed mode — sketch

The honest CTV-fork target. This is a deeper redesign, so the doc treats it as a sketch rather than a flow walkthrough.

**Funding output**: P2TR with N-of-N MuSig2 key path + CTV leaf committing to a dissolution TX + LSP-timeout-sweep leaf.

**Factory creation**: LSP unilateral. The LSP creates the funding TX, computes the committed dist TX from the slot allocation, computes TH, builds the funding output. No N-of-N ceremony.

**Slot activation**: when a client comes online to use their slot, they do a 2-of-2 MuSig2 ceremony with the LSP to instantiate their channel commit. This is per-client and asynchronous; clients don't have to be online simultaneously.

**Operation**: same channel-level mechanics as today, once a channel is activated.

**Exit**: only the CTV path. No DW tree exists.

**Rotation**: LSP creates a new factory with fresh slots; existing clients claim into the new factory (effectively a migration).

**LSP timeout sweep**: the LSP can reclaim slots that users never activate. Per-branch CSV-locked sweep leaves.

This unlocks the scaling story: LSP-funded factories with thousands of slots are feasible because there is no N-of-N coordination at funding time.

## 6. Open architectural questions

These are the questions that need resolution before either variant becomes a concrete implementation spec.

**Cross-cutting:**

1. The funding-SPK construction site is not currently visible in `src/` (it's apparently upstream of `factory_set_funding`). Either find it or add a clean `build_ctv_funding_spk` helper as part of feature 2.
2. Whether to keep the DW fallback in CTV-escape mode forever, or retire it once the CTV path is proven on Mutinynet.
3. Mempool-policy survey: validate the 1P1C package-relay path propagates across the mainnet relay graph at the rates we'd want. Test on Mutinynet first.

**CTV-committed-mode specific (the deeper open questions):**

4. **Channel activation semantics.** Before slot activation, does the client have a "virtual" channel (the LSP routes via internal accounting) or no channel at all? The Timeout-Trees model is closer to "no channel yet"; routing requires activation. This is a UX decision with real implications.
5. **What replaces the DW invalidation tree's properties?** DW exists to invalidate stale channel states; under CTV-committed mode the channel layer handles its own state invalidation independently. Likely fine, but should be explicitly walked through.
6. **LSP timeout-sweep duration and UX.** How long does the LSP wait before reclaiming a slot? What's the operator policy if a sweep-victim user comes back?
7. **Capital lock-up window.** Between funding and slot activation, the LSP has capital tied up. What's the acceptable window from the LSP operator's perspective?
8. **Rotation under no-ceremony.** Rotation today is a recurring ceremony. Under CTV-committed mode rotation = factory recreation. What's the migration path for active channels during rotation?

**Dust / topology (open, but bounded):**

9. P2TR dust threshold is 330 sat. Concretize the "sub-dust client refused at config" policy.
10. Recursive nesting topology — for CTV-committed mode, depth ≥2 nesting is the path past N≈128 per UTXO. Pick K×M for typical operator configurations.

---

## 7. Component-to-feature mapping

Adapting from the existing CTV-detection-design.md roadmap to this architecture:

| Roadmap feature | Belongs to | Notes |
|---|---|---|
| 1. CTV node-capability detection | Both variants | Shipped (PR #1) |
| 2. CTV script construction + funding output's CTV leaf | Both variants | Same script primitives needed for either |
| 3. Single-TX unilateral exit via the CTV path | Both variants | Same exit driver |
| 4. Recursive sub-factory nesting via committed templates | CTV-committed primarily | Only really useful once the all-clients-online constraint is lifted |
| 5. Client-side CTV verification + the client capability check | Both variants | Mandatory under both |
| 6. Mutinynet end-to-end campaign | Both variants | Required for either to land on mainnet |

If we ship CTV-escape mode first, features 2 + 3 + 5 + 6 deliver a real value (1-TX exit) without requiring the deeper redesign. Feature 4 only becomes meaningful under CTV-committed mode.

If we go directly to CTV-committed mode, all six features land together as a coordinated redesign, with the additional architectural work from §6 done first.

## 8. References

- BIP-119 (CTV) — [spec](https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki)
- BIP-433 (Ephemeral dust) — [spec](https://github.com/bitcoin/bips/blob/master/bip-0433.mediawiki)
- Timeout Trees (John Law) — [Bitcoin Magazine](https://bitcoinmagazine.com/technical/timeout-trees-a-solution-to-scaling-lightning-network-lsps)
- LNHANCE bundle (CTV + CSFS + IKEY + PAIRCOMMIT) — [bitcoindev post](https://groups.google.com/g/bitcoindev/c/AlMqLbmzxNA). Note: irrelevant to the factory layer; LNHANCE's extras improve channel internals, not factory exits.
- BIP-118 (ANYPREVOUT) — [spec](https://anyprevout.xyz/). Note: orthogonal to this design; APO improves channel updates (Eltoo), not factory commitments.
- Feature 1 — `docs/ctv-detection-design.md` (this fork; shipped in #1)
- LSP-funded model in current docs — `docs/deployment-coordination.md` ("LSP: Funds the factory, routes payments, manages tree state")
- The audit gap this design closes — `src/client.c:1619-1630`
- The Taproot builder we extend — `src/factory.c:99-118` (`build_musig_p2tr_spk`)
- The dist TX we commit to — `src/factory.c:3518-3580` (`factory_build_distribution_tx_unsigned`)
