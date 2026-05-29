/*
 * test_ctv_factory_build.c — unit tests for the single-layer CTV factory
 * builder (Phase B).
 *
 * Covers:
 *   - ctv_factory_build basic success
 *   - recovery_offset=0 produces a different funding SPK than
 *     recovery_offset>0 (sweep leaf changes the taptree)
 *   - total_funding_sats arithmetic
 *   - recovery_cltv_absolute computation
 *   - dist_tx_th self-consistency (re-computation matches stored)
 *   - Determinism across rebuilds
 *   - Sensitivity to user-pubkey changes
 *   - dist TX serialization byte layout (header, single input, outputs, locktime)
 *   - dist TX too-small-buffer handling
 */

#include "superscalar/ctv_factory.h"
#include "superscalar/musig.h"
#include "superscalar/tapscript.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Deterministic test secret keys: LSP + a handful of clients.  We never
 * use these for anything but pubkey derivation in the tests. */
static const unsigned char tf_seckeys[6][32] = {
    { [0 ... 31] = 0xA1 },  /* LSP */
    { [0 ... 31] = 0xB1 },  /* Client 0 */
    { [0 ... 31] = 0xB2 },  /* Client 1 */
    { [0 ... 31] = 0xB3 },  /* Client 2 */
    { [0 ... 31] = 0xB4 },  /* Client 3 */
    { [0 ... 31] = 0xB5 },  /* Spare client for sensitivity test */
};

static secp256k1_context *tf_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Populate a factory with N user-slots from our deterministic key set. */
static int tf_populate(secp256k1_context *ctx, ctv_factory_t *f,
                       uint32_t n_users, uint64_t slot_deposit_sats,
                       uint32_t recovery_offset) {
    memset(f, 0, sizeof(*f));
    f->n_users = n_users;
    f->slot_deposit_sats = slot_deposit_sats;
    f->recovery_offset_blocks = recovery_offset;
    if (!secp256k1_ec_pubkey_create(ctx, &f->lsp_pubkey, tf_seckeys[0]))
        return 0;
    for (uint32_t i = 0; i < n_users; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &f->user_pubkeys[i],
                                        tf_seckeys[1 + i]))
            return 0;
    }
    return 1;
}

/* --- ctv_factory_build --- */

int test_ctv_factory_build_basic(void) {
    secp256k1_context *ctx = tf_ctx();
    ASSERT(ctx, "ctx");

    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, /*n=*/4, /*deposit=*/10000ull, /*off=*/0),
           "populate");
    ASSERT(ctv_factory_build(ctx, &f, /*funding_height=*/100u), "build");

    ASSERT(f.total_funding_sats == 4ull * 10000ull + CTV_FACTORY_ANCHOR_SATS,
           "total_funding_sats = N * deposit + anchor");
    ASSERT(f.recovery_cltv_absolute == 0u,
           "recovery_cltv_absolute = 0 when no offset");

    /* Funding SPK is a valid P2TR (OP_1 || PUSHBYTES_32 || 32 bytes). */
    ASSERT(f.funding_spk[0] == 0x51 && f.funding_spk[1] == 0x20,
           "funding_spk starts with OP_1 OP_PUSHBYTES_32");

    /* dist_tx_th is non-zero (a sha256 essentially can never be all-zero). */
    int any_set = 0;
    for (int i = 0; i < 32; i++) if (f.dist_tx_th[i]) { any_set = 1; break; }
    ASSERT(any_set, "dist_tx_th must be a real hash, not zeros");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_recovery_offset_computes_absolute(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, /*off=*/4320u), "populate");
    ASSERT(ctv_factory_build(ctx, &f, /*funding_height=*/1000u), "build");

    ASSERT(f.recovery_cltv_absolute == 1000u + 4320u,
           "recovery_cltv_absolute = funding_height + offset");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_sweep_changes_funding_spk(void) {
    secp256k1_context *ctx = tf_ctx();

    ctv_factory_t no_sweep, with_sweep;
    ASSERT(tf_populate(ctx, &no_sweep,   4, 10000ull, 0), "populate no_sweep");
    ASSERT(tf_populate(ctx, &with_sweep, 4, 10000ull, 4320u), "populate with_sweep");

    ASSERT(ctv_factory_build(ctx, &no_sweep,   100u), "build no_sweep");
    ASSERT(ctv_factory_build(ctx, &with_sweep, 100u), "build with_sweep");

    /* Same dist_tx_th (TH depends only on outputs / sequences / locktime,
     * which are identical here — the sweep affects only the funding output's
     * taptree, not the dist TX bytes). */
    ASSERT(memcmp(no_sweep.dist_tx_th, with_sweep.dist_tx_th, 32) == 0,
           "dist_tx_th must NOT change when only the sweep leaf is added");

    /* Different funding_spk (the 32-byte tweaked output key differs). */
    ASSERT(memcmp(no_sweep.funding_spk + 2, with_sweep.funding_spk + 2, 32) != 0,
           "adding the sweep leaf MUST change the tweaked funding output key");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_build_deterministic(void) {
    secp256k1_context *ctx = tf_ctx();

    ctv_factory_t a, b;
    ASSERT(tf_populate(ctx, &a, 4, 12345ull, 4320u), "populate a");
    ASSERT(tf_populate(ctx, &b, 4, 12345ull, 4320u), "populate b");

    ASSERT(ctv_factory_build(ctx, &a, 500u), "build a");
    ASSERT(ctv_factory_build(ctx, &b, 500u), "build b");

    ASSERT(memcmp(a.dist_tx_th, b.dist_tx_th, 32) == 0,
           "identical inputs → identical TH");
    ASSERT(memcmp(a.funding_spk, b.funding_spk, 34) == 0,
           "identical inputs → identical funding SPK");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_user_change_changes_th(void) {
    secp256k1_context *ctx = tf_ctx();

    ctv_factory_t base, swapped;
    ASSERT(tf_populate(ctx, &base,    4, 10000ull, 0), "populate base");
    ASSERT(tf_populate(ctx, &swapped, 4, 10000ull, 0), "populate swapped");

    /* Swap one user's pubkey for a different one (using tf_seckeys[5]). */
    ASSERT(secp256k1_ec_pubkey_create(ctx, &swapped.user_pubkeys[2],
                                      tf_seckeys[5]),
           "swap user[2]");

    ASSERT(ctv_factory_build(ctx, &base,    100u), "build base");
    ASSERT(ctv_factory_build(ctx, &swapped, 100u), "build swapped");

    ASSERT(memcmp(base.dist_tx_th, swapped.dist_tx_th, 32) != 0,
           "changing a user's pubkey must change dist_tx_th");
    ASSERT(memcmp(base.funding_spk, swapped.funding_spk, 34) != 0,
           "changing a user's pubkey must change funding_spk too");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- ctv_factory_verify_dist_tx_th --- */

int test_ctv_factory_verify_th_self_consistent(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, 4320u), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char th_recomputed[32];
    ASSERT(ctv_factory_verify_dist_tx_th(&f, th_recomputed), "verify");
    ASSERT(memcmp(th_recomputed, f.dist_tx_th, 32) == 0,
           "recomputed TH must equal the TH stored at build time");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- ctv_factory_build_dist_tx --- */

int test_ctv_factory_dist_tx_serialization_shape(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 3, 50000ull, 0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xCC, 32);

    unsigned char tx[1024];
    size_t tx_len = sizeof(tx);
    ASSERT(ctv_factory_build_dist_tx(&f, fake_txid, 0, tx, &tx_len),
           "build_dist_tx");

    /* Expected size: 4 (ver) + 1 (in count) + 36 (outpoint) + 1 (scriptsig)
     *              + 4 (sequence) + 1 (out count varint, 4≤252) +
     *              3 * 43 (per-user outputs) + 13 (anchor) + 4 (locktime). */
    size_t expected = 4 + 1 + 36 + 1 + 4 + 1 + 3 * 43 + 13 + 4;
    ASSERT(tx_len == expected, "dist tx length matches expected layout");

    /* nVersion = 2 (LE bytes 02 00 00 00). */
    ASSERT(tx[0] == 0x02 && tx[1] == 0x00 && tx[2] == 0x00 && tx[3] == 0x00,
           "nVersion == 2");

    /* input_count = 1. */
    ASSERT(tx[4] == 0x01, "input_count = 1");

    /* prevout txid (32 bytes of 0xCC). */
    for (int i = 0; i < 32; i++)
        ASSERT(tx[5 + i] == 0xCC, "prevout txid bytes");

    /* scriptSig len = 0 at offset 5+32+4 = 41. */
    ASSERT(tx[5 + 32 + 4] == 0x00, "scriptSig length 0 (segwit input)");

    /* nSequence = 0xFFFFFFFE at offset 5+32+4+1 = 42. */
    ASSERT(tx[42] == 0xFE && tx[43] == 0xFF && tx[44] == 0xFF && tx[45] == 0xFF,
           "nSequence = 0xFFFFFFFE");

    /* output count varint at offset 46 = 0x04 (n_users + 1 = 4 ≤ 252). */
    ASSERT(tx[46] == 0x04, "output_count = 4 (3 users + 1 anchor)");

    /* nLockTime = 0 at the tail. */
    size_t lt_off = tx_len - 4;
    ASSERT(tx[lt_off] == 0 && tx[lt_off+1] == 0 &&
           tx[lt_off+2] == 0 && tx[lt_off+3] == 0,
           "nLockTime = 0");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_dist_tx_too_small_buffer(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 3, 50000ull, 0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char fake_txid[32] = {0};
    unsigned char tx[10];
    size_t tx_len = sizeof(tx);
    ASSERT(!ctv_factory_build_dist_tx(&f, fake_txid, 0, tx, &tx_len),
           "must fail when buffer is too small");
    ASSERT(tx_len > 10u,
           "tx_len must be updated to required size on failure");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Edge cases --- */

int test_ctv_factory_build_zero_users_rejected(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    memset(&f, 0, sizeof(f));
    f.n_users = 0;
    f.slot_deposit_sats = 10000ull;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &f.lsp_pubkey, tf_seckeys[0]), "lsp");
    ASSERT(!ctv_factory_build(ctx, &f, 100u), "n_users=0 must be rejected");
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_build_zero_deposit_rejected(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, /*deposit=*/0ull, 0), "populate");
    ASSERT(!ctv_factory_build(ctx, &f, 100u), "deposit=0 must be rejected");
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_build_null_rejected(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, 0), "populate");
    ASSERT(!ctv_factory_build(NULL, &f, 100u), "NULL ctx");
    ASSERT(!ctv_factory_build(ctx, NULL, 100u), "NULL factory");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- 2-of-2 leaf semantics (LSP+user channel funding output) --- */

/* Each leaf's P2TR is now over a 2-of-2 keyagg of (LSP, user_i).  So
 * changing the LSP's pubkey MUST change every leaf's scriptPubKey too
 * (this didn't hold under the v0-bare-user leaf shape). */
int test_ctv_factory_leaf_spk_depends_on_lsp_pubkey(void) {
    secp256k1_context *ctx = tf_ctx();

    ctv_factory_t a, b;
    ASSERT(tf_populate(ctx, &a, 4, 10000ull, 0), "populate a");
    ASSERT(tf_populate(ctx, &b, 4, 10000ull, 0), "populate b");

    /* Replace LSP in `b` with a different secret-key-derived pubkey. */
    ASSERT(secp256k1_ec_pubkey_create(ctx, &b.lsp_pubkey, tf_seckeys[5]),
           "swap lsp pubkey");

    ASSERT(ctv_factory_build(ctx, &a, 100u), "build a");
    ASSERT(ctv_factory_build(ctx, &b, 100u), "build b");

    /* Every user's leaf SPK depends on both LSP key (via keyagg). */
    for (uint32_t i = 0; i < a.n_users; i++) {
        ASSERT(memcmp(a.user_spks[i], b.user_spks[i], 34) != 0,
               "every leaf SPK must change when the LSP pubkey changes");
    }

    /* And so does dist_tx_th (different outputs → different outputs_hash). */
    ASSERT(memcmp(a.dist_tx_th, b.dist_tx_th, 32) != 0,
           "dist_tx_th must change when the LSP pubkey changes");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* The per-user keyagg must be byte-stable across rebuilds (the activation
 * ceremony later will rely on each side recomputing the same keyagg from
 * the same (LSP, user_i) pubkeys). */
int test_ctv_factory_user_keyagg_deterministic(void) {
    secp256k1_context *ctx = tf_ctx();

    ctv_factory_t a, b;
    ASSERT(tf_populate(ctx, &a, 4, 10000ull, 0), "populate a");
    ASSERT(tf_populate(ctx, &b, 4, 10000ull, 0), "populate b");

    ASSERT(ctv_factory_build(ctx, &a, 100u), "build a");
    ASSERT(ctv_factory_build(ctx, &b, 100u), "build b");

    for (uint32_t i = 0; i < a.n_users; i++) {
        /* Compare the serialized x-only aggregate pubkey. */
        unsigned char ax[32], bx[32];
        ASSERT(secp256k1_xonly_pubkey_serialize(ctx, ax, &a.user_keyagg[i].agg_pubkey),
               "serialize a");
        ASSERT(secp256k1_xonly_pubkey_serialize(ctx, bx, &b.user_keyagg[i].agg_pubkey),
               "serialize b");
        ASSERT(memcmp(ax, bx, 32) == 0,
               "user_keyagg[i] must be byte-stable across rebuilds");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- ctv_factory_build_funding_witness --- */

/* Witness for the CTV path with NO sweep leaf:
 *   varint(2) || varint(34) || script(34) || varint(33) || control_block(33)
 *   Total = 70 bytes.
 *
 * The script payload must be: 0x20 || dist_tx_th(32) || 0xb3 (OP_CTV). */
int test_funding_witness_no_sweep_layout(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, /*recovery=*/0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char w[128];
    size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl),
           "build witness");
    ASSERT(wl == 70u, "no-sweep witness is exactly 70 bytes");

    ASSERT(w[0] == 0x02, "stack count varint = 2");
    ASSERT(w[1] == 0x22, "script len varint = 34");
    ASSERT(w[2] == 0x20, "CTV script[0] = OP_PUSHBYTES_32");
    ASSERT(memcmp(w + 3, f.dist_tx_th, 32) == 0,
           "CTV script bytes [1..33] = factory.dist_tx_th");
    ASSERT(w[35] == 0xb3, "CTV script tail byte = OP_CTV (0xb3)");
    ASSERT(w[36] == 0x21, "control block len varint = 33 (1-leaf)");
    /* w[37] is control_block[0] = leaf_version | parity.  parity = 0 or 1. */
    ASSERT((w[37] & 0xfeu) == TAPSCRIPT_LEAF_VERSION,
           "control_block[0] leaf_version field = 0xc0");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* With sweep leaf the control block is 65 bytes and total witness is 102. */
int test_funding_witness_with_sweep_layout(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, /*recovery=*/4320u), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char w[128];
    size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl),
           "build witness");
    ASSERT(wl == 102u, "with-sweep witness is exactly 102 bytes");

    ASSERT(w[0] == 0x02 && w[1] == 0x22, "stack/script len varints");
    ASSERT(w[36] == 0x41, "control block len varint = 65 (2-leaf)");
    ASSERT((w[37] & 0xfeu) == TAPSCRIPT_LEAF_VERSION,
           "control_block[0] leaf_version field");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* The strong test: the witness must actually validate against funding_spk.
 *
 * We extract internal_key + parity from the control block, recompute the
 * merkle root from the script (and sibling, if present), tweak, and check
 * that the resulting x-only output key equals funding_spk[2..34]. */
static int verify_witness_against_spk(
    const secp256k1_context *ctx,
    const ctv_factory_t     *f,
    const unsigned char     *w,
    size_t                   wl)
{
    /* Layout (verified by layout tests above):
     *   [0]=0x02 [1]=0x22 [2..36]=script(34) [36]=cb_len [37..37+cb_len]=cb */
    (void)wl;
    const unsigned char *script = w + 2;
    size_t cb_len = w[36];
    const unsigned char *cb = w + 37;

    int parity = cb[0] & 0x01;

    /* Rebuild the CTV leaf and its tagged-hash leaf_hash. */
    tapscript_leaf_t ctv_leaf;
    if (!tapscript_build_ctv(&ctv_leaf, f->dist_tx_th)) return 0;
    if (memcmp(ctv_leaf.script, script, 34) != 0) return 0;

    unsigned char merkle_root[32];
    if (cb_len == 33u) {
        memcpy(merkle_root, ctv_leaf.leaf_hash, 32);
    } else if (cb_len == 65u) {
        /* sibling_hash is cb[33..65].  Combine with ctv_leaf.leaf_hash via
         * TapBranch.  Easier: rebuild the sweep leaf and call
         * tapscript_merkle_root. */
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL,
                                                &f->lsp_pubkey))
            return 0;
        tapscript_leaf_t sweep;
        if (!tapscript_build_cltv_timeout(&sweep, f->recovery_cltv_absolute,
                                          &lsp_xonly, ctx))
            return 0;
        /* The sibling hash in cb must match the sweep leaf hash. */
        if (memcmp(cb + 33, sweep.leaf_hash, 32) != 0) return 0;
        tapscript_leaf_t leaves[2];
        leaves[0] = ctv_leaf;
        leaves[1] = sweep;
        if (!tapscript_merkle_root(merkle_root, leaves, 2)) return 0;
    } else {
        return 0;
    }

    /* Internal key from cb[1..33] must match factory keyagg. */
    unsigned char ka_bytes[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ka_bytes, &f->keyagg.agg_pubkey))
        return 0;
    if (memcmp(cb + 1, ka_bytes, 32) != 0) return 0;

    /* Tweak; the resulting output key must equal funding_spk[2..34]. */
    secp256k1_xonly_pubkey tweaked;
    int recomputed_parity;
    if (!tapscript_tweak_pubkey(ctx, &tweaked, &recomputed_parity,
                                &f->keyagg.agg_pubkey, merkle_root))
        return 0;
    if (recomputed_parity != parity) return 0;

    unsigned char tweaked_bytes[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_bytes, &tweaked))
        return 0;
    return memcmp(tweaked_bytes, f->funding_spk + 2, 32) == 0;
}

int test_funding_witness_reproduces_spk_no_sweep(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, /*recovery=*/0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char w[128]; size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl), "witness");
    ASSERT(verify_witness_against_spk(ctx, &f, w, wl),
           "witness must reproduce funding_spk via tweak+merkle path");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_funding_witness_reproduces_spk_with_sweep(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, /*recovery=*/4320u), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char w[128]; size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl), "witness");
    ASSERT(verify_witness_against_spk(ctx, &f, w, wl),
           "witness must reproduce funding_spk via tweak+merkle path");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Witness builder must reject too-small buffers and return required size. */
int test_funding_witness_too_small_buffer(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, 0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char w[32];
    size_t wl = 32;
    ASSERT(!ctv_factory_build_funding_witness(ctx, &f, w, &wl),
           "must fail on too-small buffer");
    ASSERT(wl == 70u,
           "must write required size (70) into wl on failure");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- ctv_factory_build_dist_tx_segwit --- */

/* Segwit dist TX layout:
 *   [0..4)   nVersion = 2
 *   [4]      marker = 0x00
 *   [5]      flag   = 0x01
 *   [6]      input_count = 0x01
 *   [7..38)  prevout (txid 32 + vout 4)
 *   [39]     scriptSig len = 0
 *   [40..44) nSequence = 0xFFFFFFFE
 *   [44]     output_count varint
 *   ...      outputs
 *   ...      witness (70 or 102 bytes)
 *   last 4   nLockTime = 0
 */
int test_dist_tx_segwit_layout(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, 0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char funding_txid[32];
    memset(funding_txid, 0xaa, 32);

    unsigned char tx[2048];
    size_t tlen = sizeof(tx);
    ASSERT(ctv_factory_build_dist_tx_segwit(ctx, &f, funding_txid, 1u,
                                            tx, &tlen),
           "build segwit dist tx");

    /* Header. */
    ASSERT(tx[0] == 0x02 && tx[1]==0 && tx[2]==0 && tx[3]==0,
           "nVersion = 2");
    ASSERT(tx[4] == 0x00 && tx[5] == 0x01, "segwit marker + flag");
    ASSERT(tx[6] == 0x01, "input count = 1");

    /* Prevout. */
    for (int i = 0; i < 32; i++) ASSERT(tx[7 + i] == 0xaa, "prevout txid");
    ASSERT(tx[39] == 0x01 && tx[40] == 0 && tx[41] == 0 && tx[42] == 0,
           "prevout vout = 1");
    ASSERT(tx[43] == 0x00, "scriptSig len = 0");
    ASSERT(tx[44] == 0xfe && tx[45] == 0xff && tx[46] == 0xff && tx[47] == 0xff,
           "nSequence = 0xFFFFFFFE");
    ASSERT(tx[48] == 0x05, "output count = n_users + 1 = 5");

    /* nLockTime at end (4 bytes = 0). */
    ASSERT(tx[tlen-4]==0 && tx[tlen-3]==0 && tx[tlen-2]==0 && tx[tlen-1]==0,
           "nLockTime = 0");

    /* Witness must be the same 70 bytes the witness builder produces. */
    unsigned char w[128]; size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl), "witness");
    ASSERT(wl == 70u, "witness 70 bytes");
    /* Witness sits at tlen - 4 - 70. */
    ASSERT(memcmp(tx + tlen - 4 - 70, w, 70) == 0,
           "witness must be embedded between outputs and nLockTime");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* The segwit TX's TH-committed portion (version, inputs ex-witness, outputs,
 * locktime) must byte-match the existing non-segwit dist_tx serializer. */
int test_dist_tx_segwit_stripped_matches_unsigned(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 12500ull, /*recovery=*/0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    unsigned char funding_txid[32];
    for (int i = 0; i < 32; i++) funding_txid[i] = (unsigned char)i;

    unsigned char seg[2048]; size_t seglen = sizeof(seg);
    ASSERT(ctv_factory_build_dist_tx_segwit(ctx, &f, funding_txid, 0u,
                                            seg, &seglen),
           "segwit build");

    unsigned char un[2048]; size_t unlen = sizeof(un);
    ASSERT(ctv_factory_build_dist_tx(&f, funding_txid, 0u, un, &unlen),
           "unsigned build");

    /* Compute witness size to know stripping window. */
    unsigned char w[128]; size_t wl = sizeof(w);
    ASSERT(ctv_factory_build_funding_witness(ctx, &f, w, &wl), "witness");

    /* The two serializations differ only in:
     *   - 2 extra bytes (marker+flag) right after nVersion
     *   - witness inserted before nLockTime
     *
     * Stripped: nVersion | inputs+outputs | nLockTime should match. */
    ASSERT(memcmp(seg, un, 4) == 0, "nVersion matches");
    /* seg+4 = marker+flag.  Then seg+6 onwards = un+4 onwards up to outputs end. */
    size_t inputs_and_outputs_len = unlen - 4 /*ver*/ - 4 /*locktime*/;
    ASSERT(memcmp(seg + 6, un + 4, inputs_and_outputs_len) == 0,
           "inputs+outputs match between segwit and unsigned");
    ASSERT(memcmp(seg + seglen - 4, un + unlen - 4, 4) == 0,
           "nLockTime matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Re-using the same helper for the hierarchical funding output (which has
 * structurally the same shape). */
int test_hier_funding_witness_round_trips(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_hier_factory_t f;
    memset(&f, 0, sizeof(f));
    f.depth = 2;
    f.fanout = 4;
    f.n_users = 16;
    f.slot_deposit_sats = 10000ull;
    f.recovery_offset_blocks = 0;

    ASSERT(secp256k1_ec_pubkey_create(ctx, &f.lsp_pubkey, tf_seckeys[0]),
           "lsp pk");
    secp256k1_pubkey users[16];
    for (int i = 0; i < 16; i++) {
        unsigned char sk[32];
        memset(sk, 0xC0 + (i & 0x0f), 32);
        ASSERT(secp256k1_ec_pubkey_create(ctx, &users[i], sk), "user pk");
    }
    f.user_pubkeys = users;
    ASSERT(ctv_hier_factory_build(ctx, &f, 100u), "hier build");

    unsigned char w[128]; size_t wl = sizeof(w);
    ASSERT(ctv_hier_factory_build_funding_witness(ctx, &f, w, &wl),
           "hier witness");
    ASSERT(wl == 70u, "no-sweep witness 70 bytes");
    ASSERT(w[0] == 0x02 && w[1] == 0x22 && w[2] == 0x20 && w[35] == 0xb3,
           "witness wire format matches CTV path shape");
    ASSERT(memcmp(w + 3, f.root_th, 32) == 0,
           "script payload commits to root_th");

    /* Internal key in control block must match root_keyagg. */
    unsigned char ka_bytes[32];
    ASSERT(secp256k1_xonly_pubkey_serialize(ctx, ka_bytes,
                                            &f.root_keyagg.agg_pubkey),
           "serialize root keyagg");
    ASSERT(memcmp(w + 38, ka_bytes, 32) == 0,
           "control block internal_key = root_keyagg");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- leaf-level activation timeout (insight #13, anti-griefing) --- */

int test_ctv_factory_leaf_timeout_zero_offset_is_backward_compatible(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f_default;
    ASSERT(tf_populate(ctx, &f_default, 4, 10000ull, 0), "populate default");
    f_default.activation_offset_blocks = 0;
    ASSERT(ctv_factory_build(ctx, &f_default, 100u), "build default");
    for (uint32_t i = 0; i < f_default.n_users; i++) {
        unsigned char expected_spk[34];
        build_p2tr_script_pubkey(expected_spk, &f_default.user_keyagg[i].agg_pubkey);
        ASSERT(memcmp(expected_spk, f_default.user_spks[i], 34) == 0,
               "default leaf_spk[i] must equal P2TR(user_keyagg[i].agg_pubkey)");
    }
    ASSERT(f_default.activation_cltv_absolute == 0u,
           "activation_cltv_absolute = 0 when no offset");
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_leaf_timeout_changes_leaf_spk(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f0, f1;
    ASSERT(tf_populate(ctx, &f0, 4, 10000ull, 0), "populate f0");
    ASSERT(tf_populate(ctx, &f1, 4, 10000ull, 0), "populate f1");
    f0.activation_offset_blocks = 0;
    f1.activation_offset_blocks = 1008;
    ASSERT(ctv_factory_build(ctx, &f0, 100u), "build f0");
    ASSERT(ctv_factory_build(ctx, &f1, 100u), "build f1");
    ASSERT(f1.activation_cltv_absolute == 100u + 1008u,
           "activation_cltv_absolute = funding_height + offset");
    for (uint32_t i = 0; i < f0.n_users; i++) {
        ASSERT(memcmp(f0.user_spks[i], f1.user_spks[i], 34) != 0,
               "activation timeout must change every user leaf SPK");
    }
    ASSERT(memcmp(f0.dist_tx_th, f1.dist_tx_th, 32) != 0,
           "activation timeout must change dist_tx_th (via outputs_hash)");
    ASSERT(memcmp(f0.funding_spk + 2, f1.funding_spk + 2, 32) != 0,
           "activation timeout must change funding_spk (via TH)");
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_factory_leaf_timeout_keyagg_unchanged(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f0, f1;
    ASSERT(tf_populate(ctx, &f0, 4, 10000ull, 0), "populate f0");
    ASSERT(tf_populate(ctx, &f1, 4, 10000ull, 0), "populate f1");
    f0.activation_offset_blocks = 0;
    f1.activation_offset_blocks = 4320;
    ASSERT(ctv_factory_build(ctx, &f0, 100u), "build f0");
    ASSERT(ctv_factory_build(ctx, &f1, 100u), "build f1");
    for (uint32_t i = 0; i < f0.n_users; i++) {
        unsigned char a[32], b[32];
        ASSERT(secp256k1_xonly_pubkey_serialize(ctx, a, &f0.user_keyagg[i].agg_pubkey),
               "serialize f0 keyagg");
        ASSERT(secp256k1_xonly_pubkey_serialize(ctx, b, &f1.user_keyagg[i].agg_pubkey),
               "serialize f1 keyagg");
        ASSERT(memcmp(a, b, 32) == 0,
               "user_keyagg must be unaffected by activation_offset_blocks");
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The user's leaf SPK must equal P2TR over user_keyagg[i].agg_pubkey
 * (sanity-check the relationship between the stored keyagg and the SPK). */
int test_ctv_factory_leaf_spk_matches_user_keyagg(void) {
    secp256k1_context *ctx = tf_ctx();
    ctv_factory_t f;
    ASSERT(tf_populate(ctx, &f, 4, 10000ull, 0), "populate");
    ASSERT(ctv_factory_build(ctx, &f, 100u), "build");

    for (uint32_t i = 0; i < f.n_users; i++) {
        unsigned char expected_spk[34];
        build_p2tr_script_pubkey(expected_spk, &f.user_keyagg[i].agg_pubkey);
        ASSERT(memcmp(expected_spk, f.user_spks[i], 34) == 0,
               "user_spks[i] must equal P2TR(user_keyagg[i].agg_pubkey)");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}
