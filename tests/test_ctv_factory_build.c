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
