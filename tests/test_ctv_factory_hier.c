/*
 * test_ctv_factory_hier.c — hierarchical CTV factory builder (Phase C.1).
 *
 * Verifies the bottom-up TH chain construction across depth-d trees.
 * The single-layer-200-user cap from PR #5 / PR #6 is lifted here; the
 * key milestone tested is depth=5 fan-out=4 = 1024 users in one factory.
 *
 * Tests:
 *   - Small tree builds (depth=2, K=4, 16 users) and produces a valid
 *     funding SPK + non-zero root TH.
 *   - 1024-user scaling milestone (depth=5, K=4).
 *   - Total funding amount matches arithmetic.
 *   - Internal node count matches (K^d - 1) / (K - 1).
 *   - Determinism (rebuild with same inputs → same root TH + funding SPK).
 *   - Sensitivity (changing one user pubkey changes root TH + funding SPK).
 *   - Recovery sweep semantics carry over from single-layer.
 *   - Invalid topology (n_users != fanout^depth) rejected.
 *   - Bounds checks (depth/fanout/n_users limits).
 */

#include "superscalar/ctv_factory.h"
#include "superscalar/musig.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static secp256k1_context *hf_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Generate n_users deterministic pubkeys derived from a seed byte (so
 * test_a's user_pubkeys[i] == test_b's user_pubkeys[i] if both use the
 * same seed and i).  Caller must free the returned array. */
static secp256k1_pubkey *gen_pubkeys(secp256k1_context *ctx,
                                     uint32_t n, unsigned char seed) {
    secp256k1_pubkey *pks = malloc((size_t)n * sizeof(secp256k1_pubkey));
    if (!pks) return NULL;
    for (uint32_t i = 0; i < n; i++) {
        unsigned char sk[32];
        memset(sk, seed, 32);
        /* Mix in index so each user has a distinct key.  Use a simple
         * deterministic mixing — these are TEST keys only. */
        sk[0] ^= (unsigned char)(i & 0xff);
        sk[1] ^= (unsigned char)((i >>  8) & 0xff);
        sk[2] ^= (unsigned char)((i >> 16) & 0xff);
        sk[3] ^= (unsigned char)((i >> 24) & 0xff);
        /* Avoid the all-zero secret. */
        if (sk[0] == 0 && sk[1] == 0 && sk[2] == 0 && sk[3] == 0) sk[0] = 1;
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], sk)) {
            free(pks);
            return NULL;
        }
    }
    return pks;
}

static int populate_hier(secp256k1_context *ctx,
                         ctv_hier_factory_t *f,
                         uint8_t depth, uint8_t fanout,
                         uint32_t n_users,
                         uint64_t slot_deposit,
                         uint32_t recovery_offset,
                         unsigned char user_seed) {
    memset(f, 0, sizeof(*f));
    f->depth = depth;
    f->fanout = fanout;
    f->n_users = n_users;
    f->slot_deposit_sats = slot_deposit;
    f->recovery_offset_blocks = recovery_offset;
    unsigned char lsp_sk[32];
    memset(lsp_sk, 0xA1, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &f->lsp_pubkey, lsp_sk)) return 0;
    f->user_pubkeys = gen_pubkeys(ctx, n_users, user_seed);
    return f->user_pubkeys != NULL;
}

static void free_hier(ctv_hier_factory_t *f) {
    free((void *)f->user_pubkeys);
    f->user_pubkeys = NULL;
}

/* --- Basic recursion: depth=2, K=4 = 16 users --- */

int test_ctv_hier_depth2_16users(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    ASSERT(populate_hier(ctx, &f, /*depth*/2, /*K*/4, /*n*/16,
                          /*deposit*/10000ull, /*off*/0, /*seed*/0xB1),
           "populate");
    ASSERT(ctv_hier_factory_build(ctx, &f, /*funding_h*/0u), "build");

    /* Internal nodes for depth=2, K=4: (16-1)/3 = 5 (1 root + 4 leaf-layer). */
    ASSERT(f.n_internal_nodes == 5u, "n_internal_nodes = (K^d-1)/(K-1)");
    /* Total funding = 16*10000 + 5*240 = 161,200. */
    ASSERT(f.total_funding_sats == 16ull * 10000ull + 5ull * 240ull,
           "total_funding = N*deposit + n_internal*240");

    /* Funding SPK is a valid P2TR. */
    ASSERT(f.funding_spk[0] == 0x51 && f.funding_spk[1] == 0x20,
           "funding_spk is OP_1 PUSHBYTES_32 ...");

    /* root_th is a non-trivial hash. */
    int any = 0;
    for (int i = 0; i < 32; i++) if (f.root_th[i]) { any = 1; break; }
    ASSERT(any, "root_th must be a real hash");

    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- The headline scaling milestone: 1024 users in one factory --- */

int test_ctv_hier_depth5_1024users_scaling_unlock(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    ASSERT(populate_hier(ctx, &f, /*depth*/5, /*K*/4, /*n*/1024,
                          /*deposit*/10000ull, /*off*/0, /*seed*/0xC2),
           "populate 1024");
    ASSERT(ctv_hier_factory_build(ctx, &f, /*funding_h*/0u), "build 1024");

    /* depth=5 K=4: (1024-1)/3 = 341 internal nodes. */
    ASSERT(f.n_internal_nodes == 341u,
           "n_internal_nodes = 341 at depth=5 K=4");
    /* Total funding = 1024 * 10000 + 341 * 240 = 10,321,840. */
    ASSERT(f.total_funding_sats == 1024ull * 10000ull + 341ull * 240ull,
           "total_funding_sats arithmetic");

    /* SPK and TH are well-formed. */
    ASSERT(f.funding_spk[0] == 0x51 && f.funding_spk[1] == 0x20,
           "funding_spk shape");
    int any = 0;
    for (int i = 0; i < 32; i++) if (f.root_th[i]) { any = 1; break; }
    ASSERT(any, "root_th non-zero at 1024 users");

    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Determinism: identical inputs → identical outputs --- */

int test_ctv_hier_deterministic(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t a, b;
    ASSERT(populate_hier(ctx, &a, 3, 4, 64, 12345ull, 0, 0xD0), "pop a");
    ASSERT(populate_hier(ctx, &b, 3, 4, 64, 12345ull, 0, 0xD0), "pop b");
    ASSERT(ctv_hier_factory_build(ctx, &a, 100u), "build a");
    ASSERT(ctv_hier_factory_build(ctx, &b, 100u), "build b");

    ASSERT(memcmp(a.root_th, b.root_th, 32) == 0,
           "identical inputs → identical root_th");
    ASSERT(memcmp(a.funding_spk, b.funding_spk, 34) == 0,
           "identical inputs → identical funding_spk");

    free_hier(&a); free_hier(&b);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Sensitivity: changing one user pubkey changes the root TH --- */

int test_ctv_hier_user_change_changes_root_th(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t a, b;
    ASSERT(populate_hier(ctx, &a, 3, 4, 64, 10000ull, 0, 0xE0), "pop a");
    ASSERT(populate_hier(ctx, &b, 3, 4, 64, 10000ull, 0, 0xE0), "pop b");

    /* Swap one user pubkey in b. */
    unsigned char other_sk[32];
    memset(other_sk, 0x77, 32);
    ASSERT(secp256k1_ec_pubkey_create(ctx,
                                      (secp256k1_pubkey *)&b.user_pubkeys[42],
                                      other_sk),
           "swap user[42] pubkey");

    ASSERT(ctv_hier_factory_build(ctx, &a, 100u), "build a");
    ASSERT(ctv_hier_factory_build(ctx, &b, 100u), "build b");

    ASSERT(memcmp(a.root_th, b.root_th, 32) != 0,
           "changing a user pubkey must change root_th");
    ASSERT(memcmp(a.funding_spk, b.funding_spk, 34) != 0,
           "changing a user pubkey must change funding_spk");

    free_hier(&a); free_hier(&b);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Recovery sweep affects funding SPK but not root_th --- */

int test_ctv_hier_sweep_changes_funding_spk_only(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t no_sweep, with_sweep;
    ASSERT(populate_hier(ctx, &no_sweep,   2, 4, 16, 10000ull,  0,    0xF0), "no_sweep");
    ASSERT(populate_hier(ctx, &with_sweep, 2, 4, 16, 10000ull, 4320u, 0xF0), "with_sweep");

    ASSERT(ctv_hier_factory_build(ctx, &no_sweep,   100u), "build no_sweep");
    ASSERT(ctv_hier_factory_build(ctx, &with_sweep, 100u), "build with_sweep");

    /* root_th depends only on the dist TX template; the sweep leaf only
     * affects the funding output's taptree, not the dist TX. */
    ASSERT(memcmp(no_sweep.root_th, with_sweep.root_th, 32) == 0,
           "sweep leaf must NOT change root_th");
    ASSERT(memcmp(no_sweep.funding_spk + 2, with_sweep.funding_spk + 2, 32) != 0,
           "sweep leaf MUST change the tweaked funding output key");

    /* recovery_cltv_absolute computation */
    ASSERT(with_sweep.recovery_cltv_absolute == 100u + 4320u,
           "recovery_cltv_absolute = funding_height + offset");

    free_hier(&no_sweep); free_hier(&with_sweep);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Topology validation rejects bad inputs --- */

int test_ctv_hier_invalid_topology_rejected(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;

    /* depth=0 invalid */
    ASSERT(populate_hier(ctx, &f, 0, 4, 1, 10000ull, 0, 0xA0), "pop d0");
    ASSERT(!ctv_hier_factory_build(ctx, &f, 0u), "depth=0 rejected");
    free_hier(&f);

    /* fanout=1 invalid */
    ASSERT(populate_hier(ctx, &f, 2, 1, 1, 10000ull, 0, 0xA1), "pop K1");
    ASSERT(!ctv_hier_factory_build(ctx, &f, 0u), "fanout=1 rejected");
    free_hier(&f);

    /* n_users != fanout^depth */
    ASSERT(populate_hier(ctx, &f, 2, 4, 15, 10000ull, 0, 0xA2), "pop mismatch");
    ASSERT(!ctv_hier_factory_build(ctx, &f, 0u),
           "n_users != K^d rejected");
    free_hier(&f);

    /* depth too large */
    ASSERT(populate_hier(ctx, &f, CTV_HIER_FACTORY_MAX_DEPTH + 1, 4, 1,
                          10000ull, 0, 0xA3), "pop deep");
    ASSERT(!ctv_hier_factory_build(ctx, &f, 0u),
           "depth > MAX rejected");
    free_hier(&f);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Phase C.2 leaf outpoint resolver (PR-C2a) --- */

/* user_index out of bounds must return 0. */
int test_ctv_hier_leaf_outpoint_out_of_bounds(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    ASSERT(populate_hier(ctx, &f, 2, 4, 16, 10000ull, 0, 0xC0), "populate");
    ASSERT(ctv_hier_factory_build(ctx, &f, 0u), "build");

    unsigned char dummy_funding_txid[32];
    memset(dummy_funding_txid, 0x42, 32);
    unsigned char out_txid[32];
    uint32_t out_vout;
    ASSERT(!ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, /*user_index=*/16, dummy_funding_txid, 0,
               out_txid, &out_vout),
           "user_index >= n_users must be rejected");
    ASSERT(!ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, /*user_index=*/9999, dummy_funding_txid, 0,
               out_txid, &out_vout),
           "much-too-large user_index must be rejected");
    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* leaf_vout == user_index mod fanout (the user's position within their
 * leaf-layer subtree). */
int test_ctv_hier_leaf_outpoint_vout_is_mod_K(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    /* d=3 K=4 = 64 users → 16 leaf-layer subtrees */
    ASSERT(populate_hier(ctx, &f, 3, 4, 64, 10000ull, 0, 0xC1), "populate");
    ASSERT(ctv_hier_factory_build(ctx, &f, 0u), "build");

    unsigned char dummy_funding_txid[32];
    memset(dummy_funding_txid, 0x55, 32);

    for (uint32_t i = 0; i < f.n_users; i++) {
        unsigned char leaf_txid[32];
        uint32_t leaf_vout;
        ASSERT(ctv_hier_factory_compute_leaf_outpoint(
                   ctx, &f, i, dummy_funding_txid, 0,
                   leaf_txid, &leaf_vout),
               "resolver succeeds");
        ASSERT(leaf_vout == (i % (uint32_t)f.fanout),
               "leaf_vout must equal user_index % fanout");
    }
    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Users in the same leaf-layer subtree share leaf_txid; users in
 * different leaf-layer subtrees have different leaf_txids. */
int test_ctv_hier_leaf_outpoint_subtree_grouping(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    /* d=2 K=4 = 16 users → 4 leaf-layer subtrees of 4 users each */
    ASSERT(populate_hier(ctx, &f, 2, 4, 16, 10000ull, 0, 0xC2), "populate");
    ASSERT(ctv_hier_factory_build(ctx, &f, 0u), "build");

    unsigned char dummy_funding_txid[32];
    memset(dummy_funding_txid, 0x77, 32);

    unsigned char txid[16][32];
    uint32_t      vout[16];
    for (uint32_t i = 0; i < 16; i++) {
        ASSERT(ctv_hier_factory_compute_leaf_outpoint(
                   ctx, &f, i, dummy_funding_txid, 0, txid[i], &vout[i]),
               "resolve user");
    }

    /* Subtree 0 (users 0..3): all share txid */
    ASSERT(memcmp(txid[0], txid[1], 32) == 0, "users 0,1 same subtree");
    ASSERT(memcmp(txid[1], txid[2], 32) == 0, "users 1,2 same subtree");
    ASSERT(memcmp(txid[2], txid[3], 32) == 0, "users 2,3 same subtree");

    /* Subtree 1 (users 4..7): differ from subtree 0, share among themselves */
    ASSERT(memcmp(txid[3], txid[4], 32) != 0, "subtree 0 vs 1 differ");
    ASSERT(memcmp(txid[4], txid[5], 32) == 0, "users 4,5 same subtree");
    ASSERT(memcmp(txid[5], txid[6], 32) == 0, "users 5,6 same subtree");
    ASSERT(memcmp(txid[6], txid[7], 32) == 0, "users 6,7 same subtree");

    /* All 4 subtrees produce distinct leaf_txids */
    ASSERT(memcmp(txid[0], txid[4], 32) != 0, "subtree 0 vs 1");
    ASSERT(memcmp(txid[0], txid[8], 32) != 0, "subtree 0 vs 2");
    ASSERT(memcmp(txid[0], txid[12], 32) != 0, "subtree 0 vs 3");
    ASSERT(memcmp(txid[4], txid[8], 32) != 0, "subtree 1 vs 2");
    ASSERT(memcmp(txid[4], txid[12], 32) != 0, "subtree 1 vs 3");
    ASSERT(memcmp(txid[8], txid[12], 32) != 0, "subtree 2 vs 3");

    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Resolver result depends on funding_txid and funding_vout (changing the
 * factory's parent outpoint must change every leaf_txid). */
int test_ctv_hier_leaf_outpoint_depends_on_funding(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    ASSERT(populate_hier(ctx, &f, 2, 4, 16, 10000ull, 0, 0xC3), "populate");
    ASSERT(ctv_hier_factory_build(ctx, &f, 0u), "build");

    unsigned char tx_a[32], tx_b[32];
    memset(tx_a, 0xAA, 32);
    memset(tx_b, 0xBB, 32);

    unsigned char leaf_a[32], leaf_b[32];
    uint32_t vout_a, vout_b;

    ASSERT(ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, 0, tx_a, 0, leaf_a, &vout_a), "resolve A");
    ASSERT(ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, 0, tx_b, 0, leaf_b, &vout_b), "resolve B");

    ASSERT(memcmp(leaf_a, leaf_b, 32) != 0,
           "different funding_txid must produce different leaf_txid");

    /* Same outpoint same vout → identical */
    unsigned char leaf_c[32]; uint32_t vout_c;
    ASSERT(ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, 0, tx_a, 0, leaf_c, &vout_c), "resolve C");
    ASSERT(memcmp(leaf_a, leaf_c, 32) == 0,
           "same params → same outpoint");

    /* Changing only funding_vout also changes leaf_txid */
    ASSERT(ctv_hier_factory_compute_leaf_outpoint(
               ctx, &f, 0, tx_a, 7, leaf_c, &vout_c), "resolve C2");
    ASSERT(memcmp(leaf_a, leaf_c, 32) != 0,
           "different funding_vout must produce different leaf_txid");

    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ctv_hier_null_rejected(void) {
    secp256k1_context *ctx = hf_ctx();
    ctv_hier_factory_t f;
    ASSERT(populate_hier(ctx, &f, 2, 4, 16, 10000ull, 0, 0xB0), "populate");
    ASSERT(!ctv_hier_factory_build(NULL, &f, 0u), "NULL ctx rejected");
    ASSERT(!ctv_hier_factory_build(ctx,  NULL, 0u), "NULL factory rejected");
    /* user_pubkeys NULL */
    secp256k1_pubkey *saved = (secp256k1_pubkey *)f.user_pubkeys;
    f.user_pubkeys = NULL;
    ASSERT(!ctv_hier_factory_build(ctx,  &f,   0u), "NULL user_pubkeys rejected");
    f.user_pubkeys = saved;
    free_hier(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}
