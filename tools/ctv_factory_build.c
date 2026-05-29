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
        "  --users N                number of user slots (1..%u)\n"
        "  --slot-deposit S         per-user deposit in sats\n"
        "  --funding-height H       block height funding TX confirms at (default 0)\n"
        "  --recovery-blocks R      LSP-sweep offset; 0 = no sweep leaf (default 0)\n"
        "  --lsp-seed-hex H         32-byte LSP secret-key seed (default: all 0xA1)\n"
        "  --user-seed-base B       single byte; user_i secret = B+i (default: 0xB1)\n"
        "  --funding-txid T         32-byte funding outpoint (hex, LE wire order)\n"
        "  --funding-vout V         funding outpoint index\n"
        "    If both txid and vout are set, also emits dist_tx_segwit_hex.\n",
        prog, (unsigned int)CTV_FACTORY_MAX_USERS_SINGLE_LAYER);
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

    /* --- parse argv --- */
    for (int i = 1; i < argc; i++) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(k, "--users") && v) { n_users = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(k, "--slot-deposit") && v) { slot_deposit = (uint64_t)strtoull(v, NULL, 10); i++; }
        else if (!strcmp(k, "--funding-height") && v) { funding_height = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(k, "--recovery-blocks") && v) { recovery_blocks = (uint32_t)strtoul(v, NULL, 10); i++; }
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

    if (n_users == 0u || n_users > CTV_FACTORY_MAX_USERS_SINGLE_LAYER) {
        fprintf(stderr, "--users must be 1..%u\n", (unsigned int)CTV_FACTORY_MAX_USERS_SINGLE_LAYER);
        return 2;
    }
    if (slot_deposit == 0u) {
        fprintf(stderr, "--slot-deposit must be > 0\n");
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
     * The byte-repeated approach hit 0x00 and 0xFF (both invalid as 256-bit
     * scalars: 0x00...0 is the zero key, 0xFF...F exceeds the curve order),
     * so user counts that walked past those values would crash mid-build
     * (e.g. N=200 with default seed_base=0xB1 hits 0xFF at i=78). */
    for (uint32_t i = 0; i < n_users; i++) {
        unsigned char seed_input[5];
        seed_input[0] = user_seed_base;
        seed_input[1] = (unsigned char)(i & 0xFFu);
        seed_input[2] = (unsigned char)((i >> 8) & 0xFFu);
        seed_input[3] = (unsigned char)((i >> 16) & 0xFFu);
        seed_input[4] = (unsigned char)((i >> 24) & 0xFFu);
        unsigned char sk[32];
        sha256(seed_input, sizeof(seed_input), sk);
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
