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
