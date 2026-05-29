/*
 * test_ctv_factory.c — unit tests for the CTV (BIP-119) factory script
 * primitives shipped in Phase A:
 *
 *   - ctv_template_hash()           (BIP-119 DefaultCheckTemplateVerifyHash)
 *   - tapscript_build_ctv()         (34-byte <TH> OP_CTV tap leaf)
 *   - build_factory_funding_spk()   (funding-output SPK builder; legacy +
 *                                    CTV-escape + CTV-escape-plus-sweep)
 *
 * These are pure functions over Bitcoin-script bytes / hashes.  No live
 * node, no networking, no persistence.  Runs under `./test_superscalar
 * --unit`.
 */

#include "superscalar/tapscript.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Deterministic test secret keys for 3 participants (LSP + 2 clients). */
static const unsigned char ctv_test_seckeys[3][32] = {
    { [0 ... 31] = 0x11 },  /* LSP */
    { [0 ... 31] = 0x22 },  /* Client A */
    { [0 ... 31] = 0x33 },  /* Client B */
};

static secp256k1_context *ctv_test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int ctv_test_build_keyagg(secp256k1_context *ctx,
                                  musig_keyagg_t *ka,
                                  size_t n) {
    secp256k1_pubkey pks[3];
    for (size_t i = 0; i < n; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], ctv_test_seckeys[i]))
            return 0;
    }
    return musig_aggregate_keys(ctx, ka, pks, n);
}

/* --- ctv_template_hash --- */

/* TH must equal sha256() of the BIP-119 preimage we lay out by hand. */
int test_ctv_template_hash_matches_manual_preimage(void) {
    int32_t version = 2;
    uint32_t locktime = 0;
    uint32_t input_count = 1;
    unsigned char seq_hash[32];
    memset(seq_hash, 0x00, 32);
    uint32_t output_count = 1;
    unsigned char outs_hash[32];
    memset(outs_hash, 0x00, 32);
    uint32_t input_index = 0;

    unsigned char th[32];
    ASSERT(ctv_template_hash(version, locktime, input_count, seq_hash,
                              output_count, outs_hash, input_index, th),
           "ctv_template_hash must succeed");

    /* Build the 84-byte preimage manually and SHA-256 it. */
    unsigned char preimage[84];
    size_t pos = 0;
    preimage[pos++] = 0x02; preimage[pos++] = 0x00;
    preimage[pos++] = 0x00; preimage[pos++] = 0x00;     /* LE32 version=2 */
    memset(preimage + pos, 0, 4); pos += 4;             /* LE32 locktime=0 */
    preimage[pos++] = 0x01; preimage[pos++] = 0x00;
    preimage[pos++] = 0x00; preimage[pos++] = 0x00;     /* LE32 inputs=1 */
    memcpy(preimage + pos, seq_hash, 32); pos += 32;
    preimage[pos++] = 0x01; preimage[pos++] = 0x00;
    preimage[pos++] = 0x00; preimage[pos++] = 0x00;     /* LE32 outputs=1 */
    memcpy(preimage + pos, outs_hash, 32); pos += 32;
    memset(preimage + pos, 0, 4); pos += 4;             /* LE32 input_index=0 */

    ASSERT(pos == 84, "preimage must be exactly 84 bytes");

    unsigned char expected[32];
    sha256(preimage, 84, expected);

    ASSERT(memcmp(th, expected, 32) == 0,
           "TH must equal sha256 of the BIP-119 preimage");
    return 1;
}

int test_ctv_template_hash_deterministic(void) {
    unsigned char seq[32], outs[32];
    memset(seq, 0xAA, 32);
    memset(outs, 0xBB, 32);

    unsigned char th1[32], th2[32];
    ASSERT(ctv_template_hash(2, 100, 1, seq, 2, outs, 0, th1), "first call");
    ASSERT(ctv_template_hash(2, 100, 1, seq, 2, outs, 0, th2), "second call");
    ASSERT(memcmp(th1, th2, 32) == 0, "identical inputs → identical TH");
    return 1;
}

/* Each field independently influences the resulting TH. */
int test_ctv_template_hash_sensitive_to_every_field(void) {
    unsigned char seq[32], outs[32];
    memset(seq, 0x01, 32);
    memset(outs, 0x02, 32);

    unsigned char base[32];
    ASSERT(ctv_template_hash(2, 0, 1, seq, 1, outs, 0, base), "base TH");

    unsigned char other[32];

    /* nVersion */
    ASSERT(ctv_template_hash(3, 0, 1, seq, 1, outs, 0, other), "version varied");
    ASSERT(memcmp(base, other, 32) != 0, "version change → TH change");

    /* nLockTime */
    ASSERT(ctv_template_hash(2, 1, 1, seq, 1, outs, 0, other), "locktime varied");
    ASSERT(memcmp(base, other, 32) != 0, "locktime change → TH change");

    /* input_count */
    ASSERT(ctv_template_hash(2, 0, 2, seq, 1, outs, 0, other), "input_count varied");
    ASSERT(memcmp(base, other, 32) != 0, "input_count change → TH change");

    /* sequences_hash */
    unsigned char seq2[32];
    memset(seq2, 0x99, 32);
    ASSERT(ctv_template_hash(2, 0, 1, seq2, 1, outs, 0, other), "seq_hash varied");
    ASSERT(memcmp(base, other, 32) != 0, "sequences_hash change → TH change");

    /* output_count */
    ASSERT(ctv_template_hash(2, 0, 1, seq, 2, outs, 0, other), "output_count varied");
    ASSERT(memcmp(base, other, 32) != 0, "output_count change → TH change");

    /* outputs_hash */
    unsigned char outs2[32];
    memset(outs2, 0x88, 32);
    ASSERT(ctv_template_hash(2, 0, 1, seq, 1, outs2, 0, other), "outs_hash varied");
    ASSERT(memcmp(base, other, 32) != 0, "outputs_hash change → TH change");

    /* input_index */
    ASSERT(ctv_template_hash(2, 0, 1, seq, 1, outs, 1, other), "input_index varied");
    ASSERT(memcmp(base, other, 32) != 0, "input_index change → TH change");

    return 1;
}

int test_ctv_template_hash_null_rejected(void) {
    unsigned char seq[32] = {0};
    unsigned char outs[32] = {0};
    unsigned char th[32];

    ASSERT(!ctv_template_hash(2, 0, 1, NULL, 1, outs, 0, th),
           "NULL sequences_hash must be rejected");
    ASSERT(!ctv_template_hash(2, 0, 1, seq, 1, NULL, 0, th),
           "NULL outputs_hash must be rejected");
    ASSERT(!ctv_template_hash(2, 0, 1, seq, 1, outs, 0, NULL),
           "NULL out pointer must be rejected");
    return 1;
}

/* --- tapscript_build_ctv --- */

int test_tapscript_build_ctv_layout(void) {
    unsigned char th[32];
    for (int i = 0; i < 32; i++) th[i] = (unsigned char)(0x40 + i);

    tapscript_leaf_t leaf;
    ASSERT(tapscript_build_ctv(&leaf, th), "build_ctv must succeed");

    ASSERT(leaf.script_len == 34, "CTV leaf script must be exactly 34 bytes");
    ASSERT(leaf.script[0] == 0x20, "first byte must be OP_PUSHBYTES_32 (0x20)");
    ASSERT(memcmp(leaf.script + 1, th, 32) == 0,
           "middle 32 bytes must be the supplied TH");
    ASSERT(leaf.script[33] == 0xb3,
           "last byte must be OP_CHECKTEMPLATEVERIFY (0xb3)");

    return 1;
}

int test_tapscript_build_ctv_different_th_different_leaf_hash(void) {
    unsigned char th_a[32];
    unsigned char th_b[32];
    memset(th_a, 0xAA, 32);
    memset(th_b, 0xBB, 32);

    tapscript_leaf_t leaf_a, leaf_b;
    ASSERT(tapscript_build_ctv(&leaf_a, th_a), "build a");
    ASSERT(tapscript_build_ctv(&leaf_b, th_b), "build b");

    ASSERT(memcmp(leaf_a.leaf_hash, leaf_b.leaf_hash, 32) != 0,
           "different TH → different leaf_hash");
    return 1;
}

int test_tapscript_build_ctv_null_rejected(void) {
    unsigned char th[32] = {0};
    tapscript_leaf_t leaf;

    ASSERT(!tapscript_build_ctv(NULL, th), "NULL leaf rejected");
    ASSERT(!tapscript_build_ctv(&leaf, NULL), "NULL th rejected");
    return 1;
}

/* --- build_factory_funding_spk --- */

/* Legacy (NULL ctv_th, NULL sweep) must be byte-identical to the inline
   construction at tools/superscalar_lsp.c:3370-3391 (TapTweak with empty
   merkle root, applied to the MuSig2 keyagg, wrapped as P2TR). */
int test_funding_spk_legacy_matches_inline(void) {
    secp256k1_context *ctx = ctv_test_ctx();
    ASSERT(ctx, "ctx");

    musig_keyagg_t ka;
    ASSERT(ctv_test_build_keyagg(ctx, &ka, 3),
           "build 3-party keyagg");

    unsigned char spk_via_helper[34];
    ASSERT(build_factory_funding_spk(ctx, &ka, NULL, NULL, spk_via_helper),
           "helper legacy mode");

    /* Now reproduce the inline construction byte-for-byte. */
    secp256k1_xonly_pubkey internal_key;
    ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &internal_key, NULL,
                                              &ka.agg_pubkey),
           "internal key");

    unsigned char internal_ser[32];
    ASSERT(secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &internal_key),
           "serialize internal");

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                  &ka_copy.cache, tweak),
           "tweak add");
    secp256k1_xonly_pubkey tweaked_xonly;
    ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL,
                                              &tweaked_pk),
           "xonly tweaked");

    unsigned char spk_via_inline[34];
    build_p2tr_script_pubkey(spk_via_inline, &tweaked_xonly);

    ASSERT(memcmp(spk_via_helper, spk_via_inline, 34) == 0,
           "legacy-mode helper SPK must be byte-identical to inline path");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* CTV-only must produce a different SPK than legacy (different tweak via
   non-empty merkle root). */
int test_funding_spk_ctv_only_differs_from_legacy(void) {
    secp256k1_context *ctx = ctv_test_ctx();
    ASSERT(ctx, "ctx");

    musig_keyagg_t ka;
    ASSERT(ctv_test_build_keyagg(ctx, &ka, 3), "keyagg");

    unsigned char th[32];
    memset(th, 0x77, 32);

    unsigned char spk_legacy[34], spk_ctv[34];
    ASSERT(build_factory_funding_spk(ctx, &ka, NULL, NULL, spk_legacy),
           "legacy");
    ASSERT(build_factory_funding_spk(ctx, &ka, th, NULL, spk_ctv),
           "ctv-only");

    /* P2TR header bytes are the same; the 32-byte tweaked key differs. */
    ASSERT(spk_legacy[0] == 0x51 && spk_legacy[1] == 0x20,
           "legacy SPK prefix is OP_1 PUSHBYTES_32");
    ASSERT(spk_ctv[0] == 0x51 && spk_ctv[1] == 0x20,
           "ctv-only SPK prefix is OP_1 PUSHBYTES_32");
    ASSERT(memcmp(spk_legacy + 2, spk_ctv + 2, 32) != 0,
           "adding a CTV leaf must change the tweaked output key");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* CTV + sweep must produce a different SPK than CTV-only (2-leaf merkle root
   vs single-leaf root). */
int test_funding_spk_ctv_plus_sweep_differs_from_ctv_only(void) {
    secp256k1_context *ctx = ctv_test_ctx();
    ASSERT(ctx, "ctx");

    musig_keyagg_t ka;
    ASSERT(ctv_test_build_keyagg(ctx, &ka, 3), "keyagg");

    unsigned char th[32];
    memset(th, 0x55, 32);

    /* Build the LSP's xonly pubkey for the sweep leaf. */
    secp256k1_pubkey lsp_pk;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, ctv_test_seckeys[0]),
           "lsp pk");
    secp256k1_xonly_pubkey lsp_xonly;
    ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &lsp_pk),
           "lsp xonly");

    tapscript_leaf_t sweep_leaf;
    ASSERT(tapscript_build_cltv_timeout(&sweep_leaf, 1000000, &lsp_xonly, ctx),
           "build sweep leaf");

    unsigned char spk_ctv[34], spk_ctv_sweep[34];
    ASSERT(build_factory_funding_spk(ctx, &ka, th, NULL, spk_ctv),
           "ctv only");
    ASSERT(build_factory_funding_spk(ctx, &ka, th, &sweep_leaf, spk_ctv_sweep),
           "ctv + sweep");

    ASSERT(memcmp(spk_ctv + 2, spk_ctv_sweep + 2, 32) != 0,
           "adding the sweep leaf must change the tweaked output key");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Same inputs → same SPK; determinism is required for cross-party
   verification (every party must derive identical funding output). */
int test_funding_spk_deterministic(void) {
    secp256k1_context *ctx = ctv_test_ctx();
    ASSERT(ctx, "ctx");

    musig_keyagg_t ka;
    ASSERT(ctv_test_build_keyagg(ctx, &ka, 3), "keyagg");

    unsigned char th[32];
    memset(th, 0x42, 32);

    secp256k1_pubkey lsp_pk;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, ctv_test_seckeys[0]),
           "lsp pk");
    secp256k1_xonly_pubkey lsp_xonly;
    ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &lsp_pk),
           "lsp xonly");

    tapscript_leaf_t sweep_leaf;
    ASSERT(tapscript_build_cltv_timeout(&sweep_leaf, 500000, &lsp_xonly, ctx),
           "sweep leaf");

    unsigned char spk1[34], spk2[34];
    ASSERT(build_factory_funding_spk(ctx, &ka, th, &sweep_leaf, spk1),
           "build 1");
    ASSERT(build_factory_funding_spk(ctx, &ka, th, &sweep_leaf, spk2),
           "build 2");
    ASSERT(memcmp(spk1, spk2, 34) == 0,
           "identical inputs → byte-identical SPK");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_funding_spk_null_rejected(void) {
    secp256k1_context *ctx = ctv_test_ctx();
    musig_keyagg_t ka;
    ASSERT(ctv_test_build_keyagg(ctx, &ka, 3), "keyagg");
    unsigned char spk[34];

    ASSERT(!build_factory_funding_spk(NULL, &ka, NULL, NULL, spk),
           "NULL ctx rejected");
    ASSERT(!build_factory_funding_spk(ctx, NULL, NULL, NULL, spk),
           "NULL ka rejected");
    ASSERT(!build_factory_funding_spk(ctx, &ka, NULL, NULL, NULL),
           "NULL spk_out rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}
