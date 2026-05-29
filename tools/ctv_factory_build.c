/*
 * ctv_factory_build — Phase D-lite operator tool.
 *
 * Builds a CTV factory in-memory from CLI args and prints the artefacts a
 * Mutinynet broadcast script needs:
 *
 *   funding_spk_hex      (34 bytes, hex)  — fund this on Mutinynet
 *   total_funding_sats   — how many sats the LSP must deposit
 *   n_users              — N
 *   recovery_cltv_absolute  — 0 if no sweep, else funding_height + offset
 *   dist_tx_th_hex       — BIP-119 template hash (for verification)
 *
 * If both --funding-txid and --funding-vout are supplied, additionally
 * prints the broadcastable segwit dist TX:
 *
 *   dist_tx_segwit_hex   — feed into `bitcoin-cli sendrawtransaction`
 *                          or `submitpackage` (with CPFP child)
 *   anchor_vout          — output index of the P2A anchor (= n_users)
 *   anchor_sats          — 240
 *
 * Keys are deterministic from a seed pair so the same args always produce
 * the same factory.  This is intended for repeatable demos, not production
 * — real deployments need a real keygen flow.
 */

#include "superscalar/ctv_factory.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_print(const unsigned char *b, size_t n) {
    static const char *hx = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar(hx[b[i] >> 4]);
        putchar(hx[b[i] & 0x0f]);
    }
}

static int hex_decode(const char *s, unsigned char *out, size_t out_len) {
    size_t sl = strlen(s);
    if (sl != out_len * 2u) return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(s + i * 2u, "%2x", &b) != 1) return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --users N --slot-deposit S [options]\n"
        "\n"
        "Single-layer mode (default, N <= %u):\n"
        "  --users N                number of user slots\n"
        "  --slot-deposit S         per-user deposit in sats\n"
        "  --funding-height H       block height funding TX confirms at (default 0)\n"
        "  --recovery-blocks R      LSP-sweep offset; 0 = no sweep leaf (default 0)\n"
        "  --lsp-seed-hex H         32-byte LSP secret-key seed (default: all 0xA1)\n"
        "  --user-seed-base B       single byte; user_i seed = sha256(B||LE32(i)) (default: 0xB1)\n"
        "  --funding-txid T         32-byte funding outpoint (hex, LE wire order)\n"
        "  --funding-vout V         funding outpoint index\n"
        "    If both txid and vout are set, also emits dist_tx_segwit_hex.\n"
        "\n"
        "Hierarchical mode (when --depth and --fanout supplied):\n"
        "  --depth D                tree depth (1..%u)\n"
        "  --fanout K               tree fanout (2..%u)\n"
        "  --users N                MUST equal fanout^depth (e.g. 1024 = 4^5)\n"
        "    Hierarchical mode emits funding_spk_hex + root_th_hex.\n"
        "    Sparse-exit dist TX serialization is NOT yet implemented;\n"
        "    --funding-txid/--funding-vout are ignored in hierarchical mode.\n",
        prog,
        (unsigned int)CTV_FACTORY_MAX_USERS_SINGLE_LAYER,
        (unsigned int)CTV_HIER_FACTORY_MAX_DEPTH,
        (unsigned int)CTV_HIER_FACTORY_MAX_FANOUT);
}

/* Derive user_i's secret key as sha256(seed_base || LE32(i)).
 * Always yields a valid private key (out-of-range sha256 is a 2^-128 event). */
static void derive_user_seed(unsigned char seed_base, uint32_t i, unsigned char sk_out[32]) {
    unsigned char seed_input[5];
    seed_input[0] = seed_base;
    seed_input[1] = (unsigned char)(i & 0xFFu);
    seed_input[2] = (unsigned char)((i >> 8) & 0xFFu);
    seed_input[3] = (unsigned char)((i >> 16) & 0xFFu);
    seed_input[4] = (unsigned char)((i >> 24) & 0xFFu);
    sha256(seed_input, sizeof(seed_input), sk_out);
}

/* Hierarchical-mode build: allocates pubkey array on the heap (could be
 * 65k entries), runs ctv_hier_factory_build, prints the funding artefacts.
 * Returns 0 on success. */
static int run_hierarchical(
    secp256k1_context *ctx,
    uint8_t depth, uint8_t fanout, uint32_t n_users,
    uint64_t slot_deposit, uint32_t funding_height,
    uint32_t recovery_blocks,
    const unsigned char lsp_seed[32], unsigned char user_seed_base)
{
    /* Validate K^d == n_users. */
    uint64_t expected_n = 1;
    for (uint8_t i = 0; i < depth; i++) expected_n *= (uint64_t)fanout;
    if ((uint64_t)n_users != expected_n) {
        fprintf(stderr,
                "--users (%u) must equal fanout^depth (%u^%u = %llu)\n",
                n_users, fanout, depth, (unsigned long long)expected_n);
        return 2;
    }

    secp256k1_pubkey *user_pks = (secp256k1_pubkey *)malloc(
        (size_t)n_users * sizeof(secp256k1_pubkey));
    if (!user_pks) { fprintf(stderr, "malloc failed for %u users\n", n_users); return 1; }

    ctv_hier_factory_t f;
    memset(&f, 0, sizeof(f));
    f.depth = depth;
    f.fanout = fanout;
    f.n_users = n_users;
    f.slot_deposit_sats = slot_deposit;
    f.recovery_offset_blocks = recovery_blocks;
    f.user_pubkeys = user_pks;

    if (!secp256k1_ec_pubkey_create(ctx, &f.lsp_pubkey, lsp_seed)) {
        fprintf(stderr, "LSP seed -> pubkey failed\n");
        free(user_pks);
        return 1;
    }
    for (uint32_t i = 0; i < n_users; i++) {
        unsigned char sk[32];
        derive_user_seed(user_seed_base, i, sk);
        if (!secp256k1_ec_pubkey_create(ctx, &user_pks[i], sk)) {
            fprintf(stderr, "user[%u] sha256 seed -> pubkey failed\n", i);
            free(user_pks);
            return 1;
        }
    }

    if (!ctv_hier_factory_build(ctx, &f, funding_height)) {
        fprintf(stderr, "ctv_hier_factory_build failed\n");
        free(user_pks);
        return 1;
    }

    printf("mode=hierarchical\n");
    printf("depth=%u\n", f.depth);
    printf("fanout=%u\n", f.fanout);
    printf("n_users=%u\n", f.n_users);
    printf("n_internal_nodes=%u\n", f.n_internal_nodes);
    printf("slot_deposit_sats=%llu\n", (unsigned long long)f.slot_deposit_sats);
    printf("total_funding_sats=%llu\n", (unsigned long long)f.total_funding_sats);
    printf("recovery_cltv_absolute=%u\n", f.recovery_cltv_absolute);
    printf("anchor_sats=%u\n", (unsigned int)CTV_FACTORY_ANCHOR_SATS);

    printf("funding_spk_hex=");
    hex_print(f.funding_spk, sizeof(f.funding_spk));
    printf("\n");

    printf("root_th_hex=");
    hex_print(f.root_th, sizeof(f.root_th));
    printf("\n");

    free(user_pks);
    return 0;
}

int main(int argc, char **argv) {
    /* --- defaults --- */
    uint32_t n_users = 0;
    uint64_t slot_deposit = 0;
    uint32_t funding_height = 0;
    uint32_t recovery_blocks = 0;
    unsigned char lsp_seed[32]; memset(lsp_seed, 0xA1, 32);
    unsigned char user_seed_base = 0xB1;
    int have_funding_outpoint = 0;
    unsigned char funding_txid[32] = {0};
    uint32_t funding_vout = 0;
    int have_depth = 0;
    int have_fanout = 0;
    uint8_t depth = 0;
    uint8_t fanout = 0;

    /* --- parse argv --- */
    for (int i = 1; i < argc; i++) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(k, "--users") && v) { n_users = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(k, "--slot-deposit") && v) { slot_deposit = (uint64_t)strtoull(v, NULL, 10); i++; }
        else if (!strcmp(k, "--funding-height") && v) { funding_height = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(k, "--recovery-blocks") && v) { recovery_blocks = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(k, "--depth") && v) { depth = (uint8_t)strtoul(v, NULL, 10); have_depth = 1; i++; }
        else if (!strcmp(k, "--fanout") && v) { fanout = (uint8_t)strtoul(v, NULL, 10); have_fanout = 1; i++; }
        else if (!strcmp(k, "--lsp-seed-hex") && v) {
            if (!hex_decode(v, lsp_seed, 32)) { fprintf(stderr, "bad --lsp-seed-hex\n"); return 2; }
            i++;
        }
        else if (!strcmp(k, "--user-seed-base") && v) { user_seed_base = (unsigned char)strtoul(v, NULL, 0); i++; }
        else if (!strcmp(k, "--funding-txid") && v) {
            if (!hex_decode(v, funding_txid, 32)) { fprintf(stderr, "bad --funding-txid\n"); return 2; }
            have_funding_outpoint |= 1;
            i++;
        }
        else if (!strcmp(k, "--funding-vout") && v) { funding_vout = (uint32_t)strtoul(v, NULL, 10); have_funding_outpoint |= 2; i++; }
        else if (!strcmp(k, "-h") || !strcmp(k, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", k); usage(argv[0]); return 2; }
    }

    if (slot_deposit == 0u) {
        fprintf(stderr, "--slot-deposit must be > 0\n");
        return 2;
    }

    /* --- hierarchical mode if both --depth and --fanout are supplied --- */
    if (have_depth && have_fanout) {
        if (depth == 0u || depth > CTV_HIER_FACTORY_MAX_DEPTH) {
            fprintf(stderr, "--depth must be 1..%u\n", (unsigned int)CTV_HIER_FACTORY_MAX_DEPTH);
            return 2;
        }
        if (fanout < 2u || fanout > CTV_HIER_FACTORY_MAX_FANOUT) {
            fprintf(stderr, "--fanout must be 2..%u\n", (unsigned int)CTV_HIER_FACTORY_MAX_FANOUT);
            return 2;
        }
        if (n_users == 0u) {
            fprintf(stderr, "--users must be set in hierarchical mode (= fanout^depth)\n");
            return 2;
        }
        if (have_funding_outpoint != 0) {
            fprintf(stderr,
                    "warn: --funding-txid/--funding-vout ignored in hierarchical mode; "
                    "per-layer dist TX serialization is a follow-up\n");
        }
        secp256k1_context *ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!ctx) { fprintf(stderr, "secp256k1_context_create failed\n"); return 1; }
        int rc = run_hierarchical(ctx, depth, fanout, n_users,
                                   slot_deposit, funding_height, recovery_blocks,
                                   lsp_seed, user_seed_base);
        secp256k1_context_destroy(ctx);
        return rc;
    } else if (have_depth || have_fanout) {
        fprintf(stderr, "single-layer requires neither, hierarchical requires both, of --depth and --fanout\n");
        return 2;
    }

    /* --- single-layer mode --- */
    if (n_users == 0u || n_users > CTV_FACTORY_MAX_USERS_SINGLE_LAYER) {
        fprintf(stderr, "--users must be 1..%u in single-layer mode\n",
                (unsigned int)CTV_FACTORY_MAX_USERS_SINGLE_LAYER);
        return 2;
    }

    /* --- build factory --- */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { fprintf(stderr, "secp256k1_context_create failed\n"); return 1; }

    ctv_factory_t f;
    memset(&f, 0, sizeof(f));
    f.n_users = n_users;
    f.slot_deposit_sats = slot_deposit;
    f.recovery_offset_blocks = recovery_blocks;

    if (!secp256k1_ec_pubkey_create(ctx, &f.lsp_pubkey, lsp_seed)) {
        fprintf(stderr, "LSP seed → pubkey failed\n");
        return 1;
    }
    /* sha256(seed_base || LE32(i)) so every i yields a valid private key.
     * See derive_user_seed() for rationale (avoids 0x00 and 0xFF scalars). */
    for (uint32_t i = 0; i < n_users; i++) {
        unsigned char sk[32];
        derive_user_seed(user_seed_base, i, sk);
        if (!secp256k1_ec_pubkey_create(ctx, &f.user_pubkeys[i], sk)) {
            fprintf(stderr, "user[%u] sha256 seed -> pubkey failed\n", i);
            return 1;
        }
    }

    if (!ctv_factory_build(ctx, &f, funding_height)) {
        fprintf(stderr, "ctv_factory_build failed\n");
        return 1;
    }

    /* --- emit factory artefacts --- */
    printf("mode=single\n");
    printf("n_users=%u\n", f.n_users);
    printf("slot_deposit_sats=%llu\n", (unsigned long long)f.slot_deposit_sats);
    printf("total_funding_sats=%llu\n", (unsigned long long)f.total_funding_sats);
    printf("recovery_cltv_absolute=%u\n", f.recovery_cltv_absolute);
    printf("anchor_vout=%u\n", f.n_users);
    printf("anchor_sats=%u\n", (unsigned int)CTV_FACTORY_ANCHOR_SATS);

    printf("funding_spk_hex=");
    hex_print(f.funding_spk, sizeof(f.funding_spk));
    printf("\n");

    printf("dist_tx_th_hex=");
    hex_print(f.dist_tx_th, sizeof(f.dist_tx_th));
    printf("\n");

    /* --- optionally emit broadcastable segwit dist TX --- */
    if (have_funding_outpoint == 3) {
        unsigned char tx[16384];
        size_t tlen = sizeof(tx);
        if (!ctv_factory_build_dist_tx_segwit(ctx, &f, funding_txid,
                                              funding_vout, tx, &tlen)) {
            fprintf(stderr, "ctv_factory_build_dist_tx_segwit failed\n");
            return 1;
        }
        printf("dist_tx_segwit_hex=");
        hex_print(tx, tlen);
        printf("\n");
        printf("dist_tx_segwit_bytes=%zu\n", tlen);
    } else if (have_funding_outpoint != 0) {
        fprintf(stderr,
                "warn: only one of --funding-txid/--funding-vout supplied; "
                "skipping dist TX emission\n");
    }

    secp256k1_context_destroy(ctx);
    return 0;
}
