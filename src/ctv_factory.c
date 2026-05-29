#include "superscalar/ctv_factory.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <string.h>

/* Little-endian writers. */
static inline void w_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >>  8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}
static inline void w_u64_le(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (i * 8)) & 0xff);
}

/* The P2A anchor scriptPubKey is the fixed 4-byte sequence
 *   OP_1 (0x51) | OP_PUSHBYTES_2 (0x02) | 0x4e 0x73
 * per BIP-433 ephemeral dust standardness. */
static const unsigned char CTV_FACTORY_ANCHOR_SPK[CTV_FACTORY_ANCHOR_SPK_LEN] = {
    0x51, 0x02, 0x4e, 0x73
};

/* Build a single user's leaf as a Lightning channel funding output:
 * P2TR over a 2-of-2 MuSig2 keyagg of (LSP, user_i).  No tap leaves —
 * key-path-only, exactly like a standard LN channel funding output today.
 *
 * Side-output: the per-user keyagg is stored in *keyagg_out so the
 * Phase C activation ceremony can use it to pre-sign channel commit TXs
 * against the deferred leaf outpoint.
 *
 *   spk[34] = OP_1 || OP_PUSHBYTES_32 || x-only(keyagg(LSP, user_i))
 *
 * This is the v0 leaf shape.  The full PS leaf (channel + L-stock split,
 * with CSV-LSP-sweep on the L-stock — Items #1, #2 in the design) lands
 * once we add reserve liquidity in a later phase. */
static int build_user_leaf_spk_2of2(
    const secp256k1_context *ctx,
    const secp256k1_pubkey  *lsp_pk,
    const secp256k1_pubkey  *user_pk,
    musig_keyagg_t          *keyagg_out,
    unsigned char            spk_out34[34])
{
    secp256k1_pubkey pks[2];
    pks[0] = *lsp_pk;
    pks[1] = *user_pk;
    if (!musig_aggregate_keys(ctx, keyagg_out, pks, 2))
        return 0;
    /* keyagg_out->agg_pubkey is already x-only; serialize directly into
     * the P2TR scriptPubKey via the existing helper. */
    build_p2tr_script_pubkey(spk_out34, &keyagg_out->agg_pubkey);
    return 1;
}

/* Serialize one CTxOut into `dest`, returning bytes written.
 *   8 bytes LE amount || 1-byte compact_size script length || script.
 * Both our script lengths (34 for P2TR, 4 for P2A) fit in one byte. */
static size_t serialize_output(
    unsigned char *dest,
    uint64_t       amount_sats,
    const unsigned char *spk,
    uint8_t        spk_len)
{
    w_u64_le(dest, amount_sats);
    dest[8] = spk_len;
    memcpy(dest + 9, spk, spk_len);
    return (size_t)9 + spk_len;
}

/* Build the concatenated CTxOut serialization for sha256(...) → outputs_hash.
 * Layout:
 *   for i in 0..n_users-1:  user_output(slot_deposit_sats, user_spks[i], 34)
 *   then:                   anchor_output(240, CTV_FACTORY_ANCHOR_SPK, 4)
 * Returns total bytes written. */
static size_t serialize_outputs_concat(
    const ctv_factory_t *f,
    unsigned char       *dest,
    size_t               dest_cap)
{
    /* Worst-case size: n_users * 43 + 13.  Caller must allocate enough.
     * (Single-layer cap is 200 users → 8613 bytes max.) */
    size_t need = (size_t)f->n_users * 43u + 13u;
    if (need > dest_cap) return 0;

    size_t pos = 0;
    for (uint32_t i = 0; i < f->n_users; i++) {
        pos += serialize_output(dest + pos, f->slot_deposit_sats,
                                f->user_spks[i], 34);
    }
    pos += serialize_output(dest + pos, (uint64_t)CTV_FACTORY_ANCHOR_SATS,
                            CTV_FACTORY_ANCHOR_SPK, CTV_FACTORY_ANCHOR_SPK_LEN);
    return pos;
}

/* Compute the dist TX's BIP-119 template hash.  All factory fields the
 * TH commits to (version=2, locktime=0, single input with sequence
 * 0xFFFFFFFE, n_users+1 outputs, input_index=0) are baked here. */
static int compute_dist_tx_th(const ctv_factory_t *f, unsigned char th_out[32])
{
    /* sequences_hash = sha256(LE32(nSequence) for the single input). */
    unsigned char seq_le[4];
    w_u32_le(seq_le, 0xFFFFFFFEu);
    unsigned char sequences_hash[32];
    sha256(seq_le, sizeof(seq_le), sequences_hash);

    /* outputs_hash = sha256(concat(CTxOut_j for each output)). */
    unsigned char outputs_buf[CTV_FACTORY_MAX_USERS_SINGLE_LAYER * 43u + 13u];
    size_t outputs_len = serialize_outputs_concat(f, outputs_buf,
                                                  sizeof(outputs_buf));
    if (outputs_len == 0) return 0;

    unsigned char outputs_hash[32];
    sha256(outputs_buf, outputs_len, outputs_hash);

    return ctv_template_hash(
        /* nVersion     */ 2,
        /* nLockTime    */ 0,
        /* input_count  */ 1,
        /* sequences_h  */ sequences_hash,
        /* output_count */ f->n_users + 1u,
        /* outputs_h    */ outputs_hash,
        /* input_index  */ 0,
        /* out          */ th_out);
}

int ctv_factory_build(
    const secp256k1_context *ctx,
    ctv_factory_t           *f,
    uint32_t                 funding_block_height)
{
    if (!ctx || !f) return 0;
    if (f->n_users == 0u) return 0;
    if (f->n_users > CTV_FACTORY_MAX_USERS_SINGLE_LAYER) return 0;
    if (f->slot_deposit_sats == 0u) return 0;

    /* Total funding required = N × slot_deposit + anchor (0-fee parent). */
    f->total_funding_sats = (uint64_t)f->n_users * f->slot_deposit_sats
                            + (uint64_t)CTV_FACTORY_ANCHOR_SATS;

    /* Absolute LSP-sweep block height, if a recovery offset was requested. */
    f->recovery_cltv_absolute = (f->recovery_offset_blocks == 0u)
                                ? 0u
                                : funding_block_height + f->recovery_offset_blocks;

    /* Aggregate keys: LSP at index 0, users at 1..n_users.  This is the
     * factory's cooperative-close key path. */
    secp256k1_pubkey all_pks[CTV_FACTORY_MAX_USERS_SINGLE_LAYER + 1];
    all_pks[0] = f->lsp_pubkey;
    for (uint32_t i = 0; i < f->n_users; i++) all_pks[i + 1] = f->user_pubkeys[i];

    if (!musig_aggregate_keys(ctx, &f->keyagg, all_pks, (size_t)f->n_users + 1u))
        return 0;

    /* Per-user leaf SPKs (P2TR over the 2-of-2 LSP+user keyagg).
     * These appear verbatim in the dist TX outputs and are the bytes the
     * BIP-119 TH commits to.  The per-user keyagg is stored in
     * f->user_keyagg[i] for the activation ceremony to use later. */
    for (uint32_t i = 0; i < f->n_users; i++) {
        if (!build_user_leaf_spk_2of2(ctx, &f->lsp_pubkey,
                                       &f->user_pubkeys[i],
                                       &f->user_keyagg[i],
                                       f->user_spks[i]))
            return 0;
    }

    /* Dist TX template hash. */
    if (!compute_dist_tx_th(f, f->dist_tx_th))
        return 0;

    /* Sweep tap leaf (optional).  Built only if recovery_offset_blocks>0. */
    tapscript_leaf_t sweep_leaf;
    const tapscript_leaf_t *sweep_ptr = NULL;
    if (f->recovery_offset_blocks != 0u) {
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL,
                                                &f->lsp_pubkey))
            return 0;
        if (!tapscript_build_cltv_timeout(&sweep_leaf,
                                          f->recovery_cltv_absolute,
                                          &lsp_xonly, ctx))
            return 0;
        sweep_ptr = &sweep_leaf;
    }

    /* Funding output SPK: P2TR with CTV escape leaf and (optional) sweep leaf. */
    if (!build_factory_funding_spk(ctx, &f->keyagg, f->dist_tx_th,
                                    sweep_ptr, f->funding_spk))
        return 0;

    return 1;
}

int ctv_factory_verify_dist_tx_th(
    const ctv_factory_t *f,
    unsigned char        out_th[32])
{
    if (!f || !out_th) return 0;
    return compute_dist_tx_th(f, out_th);
}

int ctv_factory_build_dist_tx(
    const ctv_factory_t   *f,
    const unsigned char    funding_txid[32],
    uint32_t               funding_vout,
    unsigned char         *tx_out,
    size_t                *tx_len_inout)
{
    if (!f || !funding_txid || !tx_out || !tx_len_inout) return 0;

    /* Required size: 4 (version) + 1 (input count varint) +
     *                36 (outpoint) + 1 (scriptSig len=0) + 4 (sequence) +
     *                varint (output count, 1 or 3 bytes) +
     *                outputs (n_users * 43 + 13) +
     *                4 (locktime)
     *
     * Output count varint is 1 byte if (n_users + 1) ≤ 252, otherwise
     * 3 bytes (0xfd + LE16).  We support both.
     */
    size_t n_outputs = (size_t)f->n_users + 1u;
    size_t out_count_varint_len = (n_outputs <= 0xfcu) ? 1u : 3u;
    size_t outputs_bytes = (size_t)f->n_users * 43u + 13u;

    size_t need = 4u                       /* version */
                + 1u                       /* input count */
                + 36u + 1u + 4u            /* one input */
                + out_count_varint_len
                + outputs_bytes
                + 4u;                      /* locktime */

    if (*tx_len_inout < need) {
        *tx_len_inout = need;
        return 0;
    }

    size_t pos = 0;

    /* nVersion = 2 */
    w_u32_le(tx_out + pos, 2u); pos += 4;

    /* input_count = 1 */
    tx_out[pos++] = 0x01;

    /* prevout: 32-byte txid (already LE little-endian txid → wire) + 4-byte vout */
    memcpy(tx_out + pos, funding_txid, 32); pos += 32;
    w_u32_le(tx_out + pos, funding_vout); pos += 4;

    /* scriptSig length 0 (segwit) */
    tx_out[pos++] = 0x00;

    /* nSequence = 0xFFFFFFFE (final, RBF off) */
    w_u32_le(tx_out + pos, 0xFFFFFFFEu); pos += 4;

    /* output_count */
    if (out_count_varint_len == 1u) {
        tx_out[pos++] = (unsigned char)n_outputs;
    } else {
        tx_out[pos++] = 0xfd;
        tx_out[pos++] = (unsigned char)(n_outputs & 0xff);
        tx_out[pos++] = (unsigned char)((n_outputs >> 8) & 0xff);
    }

    /* outputs (same byte layout as serialize_outputs_concat) */
    for (uint32_t i = 0; i < f->n_users; i++) {
        pos += serialize_output(tx_out + pos, f->slot_deposit_sats,
                                f->user_spks[i], 34);
    }
    pos += serialize_output(tx_out + pos, (uint64_t)CTV_FACTORY_ANCHOR_SATS,
                            CTV_FACTORY_ANCHOR_SPK, CTV_FACTORY_ANCHOR_SPK_LEN);

    /* nLockTime = 0 */
    w_u32_le(tx_out + pos, 0u); pos += 4;

    *tx_len_inout = pos;
    return 1;
}

/* ====================================================================
 *  Hierarchical CTV factory (Phase C.1)
 * ==================================================================== */

#include <stdlib.h>  /* for malloc/free in keyagg construction */

/* Recursively build a subtree.
 *
 * For the leaf layer (depth_remaining == 0), constructs a dist TX whose
 * K outputs are 2-of-2 LSP+user_i P2TRs (one per leaf user in this
 * subtree), plus a P2A anchor.
 *
 * For an internal layer (depth_remaining > 0), recurses on K children,
 * each handling n_users_in_subtree/K users.  This layer's dist TX has
 * K outputs (each is the child subtree's SPK at the child's amount),
 * plus a P2A anchor.
 *
 * At every layer, the subtree's MuSig2 keyagg is computed over
 * (LSP, all users below this subtree).  The subtree's output SPK is
 * P2TR(subtree_keyagg, CTV leaf <subtree TH>) — built via the Phase A
 * helper with sweep_leaf=NULL.
 *
 * Outputs:
 *   out_th[32]     — BIP-119 TH of this subtree's dist TX
 *   *out_keyagg    — MuSig2 keyagg over LSP + this subtree's users
 *   out_spk[34]    — this subtree's output scriptPubKey
 *   *out_amount    — the amount this output should carry
 */
static int hier_build_subtree(
    const secp256k1_context *ctx,
    const secp256k1_pubkey  *lsp_pk,
    const secp256k1_pubkey  *users_slice,
    uint32_t                 n_users_in_subtree,
    uint8_t                  fanout,
    uint8_t                  depth_remaining,
    uint64_t                 slot_deposit,
    unsigned char            out_th[32],
    musig_keyagg_t          *out_keyagg,
    unsigned char            out_spk[34],
    uint64_t                *out_amount)
{
    /* Subtree keyagg over LSP + all users in this subtree.
     * Heap-allocate the temp pubkey array; could be up to ~65k+1 entries
     * at the root of a maximum-depth tree. */
    size_t n_pks = (size_t)n_users_in_subtree + 1u;
    secp256k1_pubkey *pks = (secp256k1_pubkey *)malloc(
        n_pks * sizeof(secp256k1_pubkey));
    if (!pks) return 0;
    pks[0] = *lsp_pk;
    memcpy(pks + 1, users_slice,
           (size_t)n_users_in_subtree * sizeof(secp256k1_pubkey));
    int agg_ok = musig_aggregate_keys(ctx, out_keyagg, pks, n_pks);
    free(pks);
    if (!agg_ok) return 0;

    /* Build the dist TX's outputs buffer (for outputs_hash).  Worst case:
     * K = MAX_FANOUT outputs at 43 vbytes each, plus a 13-byte anchor. */
    unsigned char outputs_buf[CTV_HIER_FACTORY_MAX_FANOUT * 43u + 13u];
    size_t pos = 0;
    uint64_t total_amount = 0;

    if (depth_remaining == 0u) {
        /* Leaf layer: K user outputs (2-of-2 LSP+user_i P2TRs). */
        for (uint32_t i = 0; i < fanout; i++) {
            unsigned char  leaf_spk[34];
            musig_keyagg_t leaf_keyagg;
            if (!build_user_leaf_spk_2of2(ctx, lsp_pk, &users_slice[i],
                                           &leaf_keyagg, leaf_spk))
                return 0;
            pos += serialize_output(outputs_buf + pos, slot_deposit,
                                    leaf_spk, 34);
            total_amount += slot_deposit;
        }
    } else {
        /* Internal layer: K child subtrees. */
        uint32_t users_per_child = n_users_in_subtree / fanout;
        for (uint32_t i = 0; i < fanout; i++) {
            unsigned char  child_th[32];
            musig_keyagg_t child_keyagg;
            unsigned char  child_spk[34];
            uint64_t       child_amount;
            if (!hier_build_subtree(ctx, lsp_pk,
                                     users_slice + (size_t)i * users_per_child,
                                     users_per_child, fanout,
                                     (uint8_t)(depth_remaining - 1u),
                                     slot_deposit,
                                     child_th, &child_keyagg, child_spk,
                                     &child_amount))
                return 0;
            pos += serialize_output(outputs_buf + pos, child_amount,
                                    child_spk, 34);
            total_amount += child_amount;
        }
    }

    /* Anchor output (last). */
    pos += serialize_output(outputs_buf + pos,
                            (uint64_t)CTV_FACTORY_ANCHOR_SATS,
                            CTV_FACTORY_ANCHOR_SPK,
                            CTV_FACTORY_ANCHOR_SPK_LEN);
    total_amount += (uint64_t)CTV_FACTORY_ANCHOR_SATS;

    /* outputs_hash = sha256(serialized_outputs). */
    unsigned char outputs_hash[32];
    sha256(outputs_buf, pos, outputs_hash);

    /* sequences_hash = sha256(LE32(0xFFFFFFFE)). */
    unsigned char seq_le[4];
    w_u32_le(seq_le, 0xFFFFFFFEu);
    unsigned char sequences_hash[32];
    sha256(seq_le, 4, sequences_hash);

    /* This subtree's dist-TX TH. */
    if (!ctv_template_hash(
            /* nVersion    */ 2,
            /* nLockTime   */ 0,
            /* input_count */ 1,
            /* sequences_h */ sequences_hash,
            /* output_count*/ (uint32_t)fanout + 1u,
            /* outputs_h   */ outputs_hash,
            /* input_index */ 0,
            /* out_th      */ out_th))
        return 0;

    /* Subtree output SPK: P2TR(subtree_keyagg, CTV leaf <subtree_TH>).
     * No sweep leaf at internal nodes in v0 (Item #14 defers depth-1 sweep). */
    if (!build_factory_funding_spk(ctx, out_keyagg, out_th, NULL, out_spk))
        return 0;

    *out_amount = total_amount;
    return 1;
}

int ctv_hier_factory_build(
    const secp256k1_context *ctx,
    ctv_hier_factory_t      *f,
    uint32_t                 funding_block_height)
{
    if (!ctx || !f || !f->user_pubkeys) return 0;
    if (f->depth == 0u  || f->depth  > CTV_HIER_FACTORY_MAX_DEPTH) return 0;
    if (f->fanout < 2u  || f->fanout > CTV_HIER_FACTORY_MAX_FANOUT) return 0;
    if (f->slot_deposit_sats == 0u) return 0;

    /* Validate n_users == fanout^depth (uniform tree only). */
    uint64_t expected_n = 1;
    for (uint8_t i = 0; i < f->depth; i++) {
        expected_n *= (uint64_t)f->fanout;
        if (expected_n > (uint64_t)CTV_HIER_FACTORY_MAX_USERS) return 0;
    }
    if ((uint64_t)f->n_users != expected_n) return 0;

    /* Internal node count = (K^d - 1) / (K - 1).  Each consumes one anchor. */
    f->n_internal_nodes = (uint32_t)((expected_n - 1u) / (uint64_t)(f->fanout - 1u));

    /* Total funding amount the LSP must deposit. */
    f->total_funding_sats = (uint64_t)f->n_users * f->slot_deposit_sats
                          + (uint64_t)f->n_internal_nodes
                          * (uint64_t)CTV_FACTORY_ANCHOR_SATS;

    /* LSP-recovery sweep absolute height (per Item #4). */
    f->recovery_cltv_absolute = (f->recovery_offset_blocks == 0u)
                                ? 0u
                                : funding_block_height + f->recovery_offset_blocks;

    /* Recursive bottom-up build.  Top-level depth_remaining = depth - 1
     * so that depth=1 → leaf layer dist TX directly off the funding output. */
    unsigned char unused_spk[34];
    uint64_t      unused_amount;
    if (!hier_build_subtree(ctx, &f->lsp_pubkey,
                             f->user_pubkeys, f->n_users, f->fanout,
                             (uint8_t)(f->depth - 1u),
                             f->slot_deposit_sats,
                             f->root_th, &f->root_keyagg,
                             unused_spk, &unused_amount))
        return 0;

    /* Funding output SPK: P2TR(root_keyagg, CTV<root_TH> + optional sweep). */
    tapscript_leaf_t        sweep_leaf;
    const tapscript_leaf_t *sweep_ptr = NULL;
    if (f->recovery_offset_blocks != 0u) {
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL,
                                                &f->lsp_pubkey))
            return 0;
        if (!tapscript_build_cltv_timeout(&sweep_leaf,
                                          f->recovery_cltv_absolute,
                                          &lsp_xonly, ctx))
            return 0;
        sweep_ptr = &sweep_leaf;
    }

    return build_factory_funding_spk(ctx, &f->root_keyagg, f->root_th,
                                      sweep_ptr, f->funding_spk);
}
