# CTV node-capability detection — design

**Fork:** superscalar-ctv
**Status:** implemented (feature 1 of the CTV arc)
**Flag:** `--ctv-mode`

## Why this exists

`OP_CHECKTEMPLATEVERIFY` (BIP-119) is `OP_NOP4` on any node that has not
activated CTV. On such a node, a script that "requires" a CTV covenant is
a **no-op** — the output is effectively **anyone-can-spend**. If
superscalar-ctv ever creates a CTV covenant output against a node that
doesn't enforce CTV, the funds in that output can be swept by anyone.

That makes node-capability detection the **non-negotiable first brick** of
the CTV arc: before any covenant output is constructed, the software must
prove the connected node actually enforces CTV, or refuse to proceed.

This document specifies the detection feature. It does **not** cover
covenant construction, recursive nesting, or template commitment — those
are later features that build on this foundation.

## What the feature does

`--ctv-mode` turns on the CTV path. At LSP startup, right after the
bitcoind connection is validated, it queries the node's CTV deployment
status and decides whether it's safe to proceed:

| Node CTV status | regtest / signet / mutinynet | mainnet |
|---|---|---|
| **active** (enforced) | proceed | proceed |
| **signaling** (started / locked_in) | warn, proceed (test only) | **refuse** |
| **defined** (known, not started) | warn, proceed (test only) | **refuse** |
| **absent** (no CTV deployment) | **refuse** | **refuse** |
| **unknown** (RPC failed / node too old) | **refuse** | **refuse** |

Rationale for the warn-vs-refuse split:
- On a **test network** you may want to exercise the wire/ceremony
  machinery before CTV is fully active. Warn loudly but allow it — with an
  explicit "do not commit real funds" notice.
- On **mainnet**, an unenforced CTV output is a fund-loss bug, full stop.
  Refuse unless `active`.
- **absent / unknown** is always a refuse: the node either has no CTV
  concept or we couldn't determine it. Creating covenant outputs there is
  the exact anyone-can-spend failure this feature exists to prevent.

When `--ctv-mode` is **off** (the default), the check is skipped entirely
and the binary behaves identically to upstream SuperScalar.

## How detection works

Bitcoin Core (25.0+) exposes soft-fork deployment status via the
**`getdeploymentinfo`** RPC. The CTV activation client surfaces a
deployment for CTV; on a vanilla node it is absent.

```
regtest_node_ctv_status(rt)
  └─ regtest_exec(rt, "getdeploymentinfo", "")   // live RPC
       └─ regtest_parse_ctv_status(json)         // pure parser (unit-tested)
```

`regtest_parse_ctv_status()` (in `src/regtest.c`, declared in
`include/superscalar/regtest.h`) is a **pure function over the JSON
string**, so the mapping logic is unit-tested without a live node
(`tests/test_ctv_detect.c`). It:

1. Parses the result, looks for `deployments`.
2. Finds a deployment named `checktemplateverify` or `ctv`.
3. Fallback: scans for any `bip9` deployment on **bit 5** (CTV's
   conventional deployment bit in the activation client).
4. Maps the deployment's `active` boolean / `bip9.status` to the enum:
   - `active:true` or `status:"active"` → `REGTEST_CTV_ACTIVE`
   - `status:"started"` / `"locked_in"` → `REGTEST_CTV_SIGNALING`
   - `status:"defined"` → `REGTEST_CTV_DEFINED`
   - `status:"failed"` → `REGTEST_CTV_ABSENT`
   - no `deployments` object → `REGTEST_CTV_UNKNOWN` (node too old / errored)
   - no CTV deployment found → `REGTEST_CTV_ABSENT`
   - NULL / unparseable → `REGTEST_CTV_UNKNOWN`

### Example getdeploymentinfo shape (CTV node)

```json
{
  "deployments": {
    "checktemplateverify": {
      "type": "bip9",
      "active": false,
      "bip9": { "bit": 5, "status": "started", "start_time": 1774809000, "timeout": 1806345000 }
    }
  }
}
```

## Implementation map

| File | Change |
|---|---|
| `include/superscalar/regtest.h` | `regtest_ctv_status_t` enum + `regtest_parse_ctv_status()`, `regtest_node_ctv_status()`, `regtest_ctv_status_str()` decls |
| `src/regtest.c` | the three functions (cJSON parse of getdeploymentinfo) |
| `tools/superscalar_lsp.c` | `--ctv-mode` flag + startup check (warn/refuse) + help text |
| `tests/test_ctv_detect.c` | 10 unit tests over the pure parser |
| `tests/test_main.c` + `CMakeLists.txt` | register the test suite |

## Deliberately out of scope (later CTV features)

- CTV covenant **output construction** (the `OP_CHECKTEMPLATEVERIFY` script + committed template hash)
- The CTV **distribution-transaction** exit path (single-tx unilateral exit per the README design)
- **Recursive nesting** of covenant-committed sub-factories
- Any **wire-protocol** changes
- **Client-side** CTV detection (this feature is LSP-only; the client check lands when the client validates CTV outputs)

## Roadmap (what builds on this)

1. **[this feature] CTV node-capability detection** — refuse to run against a non-CTV node ✅
2. CTV script construction — build an `OP_CHECKTEMPLATEVERIFY` output committing to a distribution TX
3. Single-tx unilateral exit — spend the CTV leaf to pay every user their balance in one transaction, no cooperation, no timelock
4. Recursive sub-factory nesting via committed templates (the equivocation-free scaling unlock)
5. Client-side CTV verification + the client capability check
6. Mutinynet end-to-end campaign

## Testing

- **Unit:** `tests/test_ctv_detect.c` feeds mock getdeploymentinfo payloads (active / started / locked_in / defined / failed / alt-name / bit-5 fallback / absent / no-deployments / NULL / garbage) and asserts the enum mapping. Runs with `./test_superscalar --unit` — no node required. Verifies the parser *given* a payload; it cannot verify the payload shape a real node actually returns.
- **Live two-node (CI):** `tools/test_ctv_node_detection.sh`, driven by the `ctv-node-detection` CI job, stands up two real regtest nodes of the same base version (28.1) so CTV enforcement is the only variable:
  - **vanilla Bitcoin Core 28.1** (no CTV) — `--ctv-mode` must **refuse** (exit non-zero, anyone-can-spend message);
  - **Bitcoin Inquisition 28.1-inq** (CTV enforced) — `--ctv-mode` must **proceed**.

  Both binaries are downloaded and checksum-verified (no fork compile). This is the test that exercises the **real `getdeploymentinfo` shape end-to-end** — it would catch a detector that, e.g., expects a deployment entry the real node reports differently. It dumps the live `getdeploymentinfo` CTV deployment for both nodes so the actual shape is on the record.
- **Manual (signet/Mutinynet, optional):** `superscalar_lsp --ctv-mode --network signet ...` against a Mutinynet node for a non-regtest CTV confirmation.

## References

- BIP-119: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
- CTV activation client: https://github.com/ctv-activation/activation-client
- Mutinynet: https://mutinynet.com
- The CTV exit-design intent: see this fork's README.
