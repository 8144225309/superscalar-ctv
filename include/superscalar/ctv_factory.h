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

#endif /* SUPERSCALAR_CTV_FACTORY_H */
