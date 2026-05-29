#ifndef SUPERSCALAR_CTV_FACTORY_H
#define SUPERSCALAR_CTV_FACTORY_H

#include "musig.h"
#include "tapscript.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stddef.h>

/*
 * CTV-committed channel-factory primitives (Phase B: single-layer).
 *
 * A CTV factory is a single Bitcoin UTXO that the LSP funds.  Its
 * scriptPubKey is a P2TR with two spending paths:
 *
 *   - key path: N-of-N MuSig2 cooperative close (LSP + all users sign).
 *   - script path: <root_TH> OP_CHECKTEMPLATEVERIFY  — anyone may broadcast
 *     the committed dist TX, materializing every user's slot output as a
 *     plain P2TR UTXO at the user's pubkey.
 *
 * Optionally a second tap leaf is included for the LSP-recovery sweep:
 *     <recovery_cltv_absolute> OP_CLTV OP_DROP <LSP_xonly_pk> OP_CHECKSIG
 *
 * The whole tree is committed at funding time.  No client ceremony is
 * needed: each user's pubkey is baked into the dist TX template the CTV
 * leaf commits to.  Any party can fire the CTV escape unilaterally to
 * dissolve the factory and pay each user their slot deposit.
 *
 * This v0 deliberately omits the channel layer at the leaves (no L-stock,
 * no per-user 2-of-2 channel commits, no HTLC plumbing).  The leaf is a
 * plain P2TR to the user's key.  That keeps the single-layer factory the
 * simplest demonstrable form of CTV-committed UTXO sharing.
 */

/* Maximum users per single CTV factory in the single-layer demo.
 * Bounded by the dist TX vbyte budget at K=N (no hierarchy yet).
 * Per-user output is ~43 vbytes; we cap well below the standardness limit.
 */
#define CTV_FACTORY_MAX_USERS_SINGLE_LAYER 200

/* P2A anchor amount (BIP-433 ephemeral dust). */
#define CTV_FACTORY_ANCHOR_SATS 240u

/* P2A anchor scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes). */
#define CTV_FACTORY_ANCHOR_SPK_LEN 4

typedef struct {
    /* --- Inputs (caller fills in before ctv_factory_build) --- */

    /* Number of user slots in this factory.  1..CTV_FACTORY_MAX_USERS_SINGLE_LAYER. */
    uint32_t n_users;

    /* Per-user slot deposit (sats).  LSP capital allocated to each user. */
    uint64_t slot_deposit_sats;

    /* Operator-configured LSP-recovery sweep offset.
     *   0  → no sweep leaf (perpetual factory, no LSP recovery)
     *   >0 → recovery_cltv_absolute = funding_block_height + this value
     * See CTV_FACTORY_DESIGN.md Item #4. */
    uint32_t recovery_offset_blocks;

    /* Operator-configured per-LEAF activation timeout offset (anti-griefing).
     *   0  → no leaf-level timeout (leaf is key-path-only, PR #6 behavior)
     *   >0 → activation_cltv_absolute = funding_block_height + this value
     *        and each user leaf gets an LSP-only timeout tap leaf:
     *        <activation_cltv> OP_CLTV OP_DROP <LSP_xonly> OP_CHECKSIG
     *
     * Inactive users (didn't sign their Phase C.2 channel commit by the
     * deadline) have their slot reclaimable by the LSP via the leaf-level
     * tap leaf, bounding the LSP's capital risk under enrollment Sybil
     * griefing.  Legitimate users defeat the timeout by broadcasting
     * their pre-signed channel commit. */
    uint32_t activation_offset_blocks;

    /* LSP's pubkey.  At index 0 in the N-of-N keyagg. */
    secp256k1_pubkey lsp_pubkey;

    /* User pubkeys, indices 0..n_users-1.  Order matters: each user's
     * output in the dist TX appears in the order given here. */
    secp256k1_pubkey user_pubkeys[CTV_FACTORY_MAX_USERS_SINGLE_LAYER];

    /* --- Computed by ctv_factory_build --- */

    /* Total amount that must be deposited into the funding output:
     *   n_users * slot_deposit_sats + CTV_FACTORY_ANCHOR_SATS
     * The dist TX is strictly zero-fee per BIP-433. */
    uint64_t total_funding_sats;

    /* Recovery sweep absolute block height (0 if recovery_offset_blocks==0). */
    uint32_t recovery_cltv_absolute;

    /* Leaf-level activation timeout absolute block height
     * (0 if activation_offset_blocks==0). */
    uint32_t activation_cltv_absolute;

    /* MuSig2 keyagg over {LSP, user_0, ..., user_{n-1}}.
     * Used as the internal key of the funding output's P2TR (key path =
     * cooperative N-of-N close). */
    musig_keyagg_t keyagg;

    /* BIP-119 template hash of the dist TX. */
    unsigned char dist_tx_th[32];

    /* 34-byte P2TR scriptPubKey of the funding output.  Built via
     * build_factory_funding_spk with the CTV leaf and (optional) sweep leaf. */
    unsigned char funding_spk[34];

    /* Per-user 2-of-2 MuSig2 keyagg over (LSP, user_i).
     *
     * The user's leaf P2TR (user_spks[i]) is built over this keyagg's
     * aggregate x-only key (no script leaves at this layer in v0).  This
     * makes each leaf a standard Lightning channel funding output:
     *   - cooperative spend (Phase C): 2-of-2 MuSig2 sig (LSP + user)
     *   - channel commit pre-signing (Phase C): per-user MuSig2 ceremony
     *     produces a channel commit TX whose input is the *deferred*
     *     leaf outpoint (which materializes once the CTV escape fires)
     *
     * Stored at factory build time so the activation ceremony can recover
     * it without recomputing from raw pubkeys. */
    musig_keyagg_t user_keyagg[CTV_FACTORY_MAX_USERS_SINGLE_LAYER];

    /* Each user's leaf P2TR scriptPubKey, precomputed at build time.
     *
     * Built as P2TR over user_keyagg[i].agg_pubkey (the 2-of-2 LSP+user
     * MuSig2 aggregate).  Key-path-only: there are no tap leaves at the
     * leaf, exactly like a standard Lightning channel funding output.
     *
     * dist_tx output i (0-based) has script_pubkey == user_spks[i].
     * (Output n_users is the P2A anchor.) */
    unsigned char user_spks[CTV_FACTORY_MAX_USERS_SINGLE_LAYER][34];
} ctv_factory_t;

/*
 * Build a single-layer CTV factory.
 *
 * Caller pre-populates the input fields of `factory`:
 *   n_users, slot_deposit_sats, recovery_offset_blocks,
 *   lsp_pubkey, user_pubkeys[0..n_users-1].
 *
 * This function fills in the computed fields:
 *   total_funding_sats, recovery_cltv_absolute, keyagg,
 *   dist_tx_th, funding_spk, user_spks[].
 *
 * `funding_block_height` is added to recovery_offset_blocks to produce
 * the absolute CLTV value used in the LSP-sweep tap leaf (if any).
 *
 * Returns 1 on success.
 */
int ctv_factory_build(
    const secp256k1_context *ctx,
    ctv_factory_t           *factory,
    uint32_t                 funding_block_height);

/*
 * Serialize the unsigned dist TX into `tx_out`.  The TX has:
 *   - nVersion = 2
 *   - 1 input (caller provides funding outpoint via the args)
 *   - n_users + 1 outputs:
 *       0..n_users-1 : per-user P2TR (script = user_spks[i],
 *                                     amount = slot_deposit_sats)
 *       n_users      : P2A anchor (240 sats)
 *   - nLockTime = 0
 *
 * The input's scriptSig is empty (segwit).  Witness is NOT included
 * (caller fills it in: CTV script-path or N-of-N key-path).
 *
 * On entry, *tx_len_inout is the size of tx_out.  On success it's set to
 * the number of bytes written.
 *
 * Returns 1 on success.
 */
int ctv_factory_build_dist_tx(
    const ctv_factory_t   *factory,
    const unsigned char    funding_txid[32],
    uint32_t               funding_vout,
    unsigned char         *tx_out,
    size_t                *tx_len_inout);

/*
 * Compute the dist TX template hash from a built factory.  This is
 * primarily a self-check: ctv_factory_build already stored it in
 * factory->dist_tx_th, and this function re-derives it for validation.
 *
 * Used by tests and (in production) by the client-side verification
 * step that confirms the factory was funded as advertised.
 *
 * Returns 1 on success.
 */
int ctv_factory_verify_dist_tx_th(
    const ctv_factory_t *factory,
    unsigned char        out_th[32]);

/*
 * Build the script-path witness that spends the funding output via the
 * CTV escape leaf.
 *
 * Witness stack (BIP-341 script path):
 *   item 0: the CTV leaf script  — 34 bytes: <root_TH> OP_CHECKTEMPLATEVERIFY
 *   item 1: the control block    — 33 bytes (CTV-only taptree)
 *                                  or 65 bytes (CTV + LSP-sweep taptree)
 *
 * Output is in Bitcoin wire format with the leading stack-count varint:
 *   varint(2) || varint(34) || script(34)
 *               || varint(33|65) || control_block(33|65)
 *
 * Total size: 70 bytes (recovery_offset_blocks == 0)
 *          or 102 bytes (recovery_offset_blocks > 0; sweep sibling included).
 *
 * On entry, *witness_len_inout is the buffer size; on success it is set to
 * the number of bytes written.  On too-small-buffer the required size is
 * written and 0 is returned.
 *
 * Returns 1 on success.
 */
int ctv_factory_build_funding_witness(
    const secp256k1_context *ctx,
    const ctv_factory_t     *factory,
    unsigned char           *witness_out,
    size_t                  *witness_len_inout);

/*
 * Build the broadcastable, segwit-formatted dist TX that spends the
 * funding output via the CTV escape path.  Layout:
 *
 *   nVersion(4) || 0x00 || 0x01                  (segwit marker + flag)
 *     || input_count_varint || input
 *     || output_count_varint || outputs
 *     || witness_for_input_0                     (built via _funding_witness)
 *     || nLockTime(4)
 *
 * The result is ready for `bitcoin-cli sendrawtransaction` and can be the
 * parent in a `submitpackage [parent_hex, cpfp_child_hex]` call where the
 * child spends the P2A anchor at output index `factory->n_users`.
 *
 * Returns 1 on success; sets *tx_len_inout to the required size on
 * too-small-buffer.
 */
int ctv_factory_build_dist_tx_segwit(
    const secp256k1_context *ctx,
    const ctv_factory_t     *factory,
    const unsigned char      funding_txid[32],
    uint32_t                 funding_vout,
    unsigned char           *tx_out,
    size_t                  *tx_len_inout);


/* ====================================================================
 *  Hierarchical CTV factory (Phase C.1)
 *
 *  Generalises the single-layer builder above to depth-d trees with
 *  uniform fan-out K.  Total users = K^depth.  The factory funding
 *  output's CTV leaf commits to a root-layer dist TX; that TX's K
 *  outputs each carry their own CTV leaf committing to the next-layer
 *  dist TX; recursion terminates at the leaf layer where each output
 *  is a 2-of-2 LSP+user P2TR (the channel funding output shape from
 *  PR #6).
 *
 *  This is what lifts the user cap from 200 (single-layer) into the
 *  thousands.  Per-user sparse-exit cost scales as O(depth × K)
 *  vbytes — see CTV_FACTORY_DESIGN.md §3 for the numerics.
 *
 *  Note: per-layer LSP-sweep tap leaves (Item #14 of the design — the
 *  depth-1 sweep) are NOT in this v0 hierarchical builder; we add them
 *  in a follow-up once the basic tree mechanics are proven.
 * ==================================================================== */

/* Topological bounds for the hierarchical builder. */
#define CTV_HIER_FACTORY_MAX_USERS    65536u    /* K=4 depth=8 = 65,536       */
#define CTV_HIER_FACTORY_MAX_FANOUT   16u
#define CTV_HIER_FACTORY_MAX_DEPTH    8u

typedef struct {
    /* --- Inputs (caller fills in) --- */

    uint8_t  depth;                  /* 1..CTV_HIER_FACTORY_MAX_DEPTH       */
    uint8_t  fanout;                 /* K. 2..CTV_HIER_FACTORY_MAX_FANOUT   */
    uint32_t n_users;                /* MUST equal fanout^depth             */
    uint64_t slot_deposit_sats;      /* per-leaf user                       */
    uint32_t recovery_offset_blocks; /* 0 = no LSP-sweep leaf on funding TX */
    uint32_t activation_offset_blocks; /* 0 = no leaf-level timeout
                                        * (see ctv_factory_t for semantics) */

    secp256k1_pubkey lsp_pubkey;
    /* Pointer to caller-owned array of n_users user pubkeys.  Indexing
     * is left-to-right at the leaf layer: user_pubkeys[0] is the first
     * leaf of the leftmost leaf-layer subtree; user_pubkeys[n_users-1]
     * is the rightmost. */
    const secp256k1_pubkey *user_pubkeys;

    /* --- Computed by ctv_hier_factory_build --- */

    /* Number of internal dist-TX nodes in the tree: (K^d - 1) / (K - 1).
     * Each consumes one 240-sat P2A anchor from the funding amount. */
    uint32_t n_internal_nodes;

    /* Total funding required = n_users * slot_deposit + n_internal * 240. */
    uint64_t total_funding_sats;

    /* Absolute LSP-recovery-sweep block height (0 if no sweep). */
    uint32_t recovery_cltv_absolute;

    /* Leaf-level activation timeout absolute block height
     * (0 if activation_offset_blocks==0). */
    uint32_t activation_cltv_absolute;

    /* Root TH and root keyagg (the funding output's CTV leaf commits to
     * this TH, and the funding output's internal key is this keyagg). */
    unsigned char  root_th[32];
    musig_keyagg_t root_keyagg;

    /* The funding output's 34-byte P2TR scriptPubKey. */
    unsigned char funding_spk[34];
} ctv_hier_factory_t;

/*
 * Build a hierarchical CTV factory.
 *
 * Validates that fanout^depth == n_users (uniform tree only in v0).
 * Then walks the tree bottom-up: at each subtree, computes the
 * subtree's dist-TX TH, the subtree's keyagg over its users, and the
 * subtree's output script (P2TR with CTV leaf committing to its TH).
 *
 * At the root, builds the funding output's scriptPubKey via the
 * Phase A helper (with optional LSP-sweep leaf when recovery_offset
 * is non-zero).
 *
 * Returns 1 on success.
 */
int ctv_hier_factory_build(
    const secp256k1_context  *ctx,
    ctv_hier_factory_t       *factory,
    uint32_t                  funding_block_height);

/*
 * Hierarchical-factory analog of ctv_factory_build_funding_witness.
 *
 * The funding output is structurally identical (P2TR with CTV leaf, optional
 * LSP-sweep leaf); only the source struct differs.  Output format and size
 * are exactly the same as the single-layer variant (70 or 102 bytes).
 *
 * Returns 1 on success.
 */
int ctv_hier_factory_build_funding_witness(
    const secp256k1_context  *ctx,
    const ctv_hier_factory_t *factory,
    unsigned char            *witness_out,
    size_t                   *witness_len_inout);

/*
 * Build the LEGACY (non-segwit) serialization of a Phase C.2 channel
 * commit TX.  The TX spends the user's leaf outpoint (typically deferred,
 * derived via ctv_hier_factory_compute_leaf_outpoint) and produces two
 * outputs:
 *   [0] to_user — P2TR(to_user_xonly), pays the user their channel balance
 *   [1] to_lsp  — P2TR(to_lsp_xonly), pays the LSP their channel balance
 *
 * v0 channel commit shape (simplified for the demo): key-path-only P2TR
 * outputs for both sides.  No HTLCs, no CSV delay on to_user, no
 * revocation script path.  These compose on top in Phase C.2 v1+.
 *
 * Layout (137 bytes total):
 *   nVersion(4) || input_count(1)=1
 *     || prevout txid(32) || prevout vout(4)
 *     || scriptSig_len(1)=0
 *     || nSequence(4)=0xFFFFFFFE
 *     || output_count(1)=2
 *     || amount(8) || spk_len(1)=0x22 || P2TR_to_user(34)    [43 bytes]
 *     || amount(8) || spk_len(1)=0x22 || P2TR_to_lsp(34)     [43 bytes]
 *     || nLockTime(4)=0
 *
 * The TXID is sha256d of these bytes.  C2c will compute the BIP-341
 * keypath sighash from this serialization (plus knowledge of the leaf's
 * previous output) and sign with the 2-of-2 LSP+user keyagg.
 *
 * to_user_sats + to_lsp_sats must be less than the leaf's slot_deposit
 * (the difference is the channel commit's fee).
 *
 * Returns 1 on success; sets *tx_len_inout to the required size on
 * too-small-buffer.
 */
/*
 * Compute the BIP-341 key-path sighash (SIGHASH_DEFAULT) for a Phase C.2
 * channel commit TX.
 *
 * Inputs:
 *   commit_tx, commit_tx_len: bytes produced by
 *     ctv_factory_build_channel_commit_tx() — exactly 137 bytes for v0.
 *   leaf_spk[34]: the leaf's 34-byte P2TR scriptPubKey (the previous output
 *     being spent — comes from factory's user_spks[i] field).
 *   leaf_amount: the leaf's value in sats (= factory->slot_deposit_sats).
 *
 * Output:
 *   sighash_out[32]: the 32-byte BIP-341 message digest, to be signed.
 *
 * This is what `musig_sign_taproot` consumes as `msg32`.
 *
 * Returns 1 on success.
 */
int ctv_factory_compute_channel_commit_sighash(
    const unsigned char *commit_tx,
    size_t               commit_tx_len,
    const unsigned char  leaf_spk[34],
    uint64_t             leaf_amount,
    unsigned char        sighash_out[32]);

/*
 * One-shot Phase C.2 channel commit signing (PR-C2c, all-local demo flow).
 *
 * Performs the 2-of-2 MuSig2 ceremony between LSP and user, producing a
 * 64-byte BIP-340 Schnorr signature that authorizes the channel commit
 * TX to spend the user's leaf via the key path.
 *
 *   leaf_merkle_root: NULL when the leaf has no tap leaves
 *                    (= activation_offset_blocks == 0 in the factory),
 *                    or the leaf's tap-tree merkle root otherwise (i.e.
 *                    the timeout tap leaf hash from PR #13 when set).
 *
 * `user_keyagg` is mutated in place by the taproot tweak.  For demos
 * that need to sign multiple commits with the same keyagg, pass a
 * working copy of factory->user_keyagg[i].
 *
 * Returns 1 on success.
 */
int ctv_factory_sign_channel_commit(
    const secp256k1_context *ctx,
    const unsigned char     *commit_tx,
    size_t                   commit_tx_len,
    const unsigned char      leaf_spk[34],
    uint64_t                 leaf_amount,
    const unsigned char      lsp_sk[32],
    const unsigned char      user_sk[32],
    musig_keyagg_t          *user_keyagg,
    const unsigned char     *leaf_merkle_root,
    unsigned char            sig64_out[64]);

int ctv_factory_build_channel_commit_tx(
    const unsigned char            leaf_txid[32],
    uint32_t                       leaf_vout,
    const secp256k1_xonly_pubkey  *to_user_xonly,
    const secp256k1_xonly_pubkey  *to_lsp_xonly,
    uint64_t                       to_user_sats,
    uint64_t                       to_lsp_sats,
    const secp256k1_context       *ctx,
    unsigned char                 *tx_out,
    size_t                        *tx_len_inout);

/*
 * Compute the deferred leaf outpoint for user_index in a hierarchical
 * CTV factory.
 *
 * This is the foundation of Phase C.2 channel commit pre-signing: each
 * user's "leaf" UTXO doesn't physically exist pre-dissolution, but its
 * outpoint is deterministic because every intermediate dist TX is
 * CTV-committed (its bytes are fully determined at funding time).
 *
 * Walks from the root dist TX (input = funding outpoint) down to
 * user_index's leaf-layer dist TX, computing each layer's TXID via
 * sha256d of the legacy (non-segwit) serialization.  The leaf vout is
 * user_index modulo fanout (the user's position within their leaf-layer
 * parent's K children).
 *
 * On a depth-d tree this walks d layers.  Memory peak is bounded by one
 * layer's per-output buffer (~K * 43 + 13 bytes).  CPU cost is
 * O(d * K * subtree_users) for the SPK derivations along the path —
 * about 30-60s at d=8 K=4 (65k users).
 *
 * Returns 1 on success.  user_index >= factory->n_users returns 0.
 */
int ctv_hier_factory_compute_leaf_outpoint(
    const secp256k1_context  *ctx,
    const ctv_hier_factory_t *factory,
    uint32_t                  user_index,
    const unsigned char       funding_txid[32],
    uint32_t                  funding_vout,
    unsigned char             out_leaf_txid[32],
    uint32_t                 *out_leaf_vout);

#endif /* SUPERSCALAR_CTV_FACTORY_H */
