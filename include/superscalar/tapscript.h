#ifndef SUPERSCALAR_TAPSCRIPT_H
#define SUPERSCALAR_TAPSCRIPT_H

#include "types.h"
#include "tx_builder.h"
#include "musig.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdint.h>

#define TAPSCRIPT_MAX_SCRIPT 128
#define TAPSCRIPT_LEAF_VERSION 0xc0

typedef struct {
    unsigned char script[TAPSCRIPT_MAX_SCRIPT];
    size_t script_len;
    unsigned char leaf_hash[32];
} tapscript_leaf_t;

/* Build hashlock script: OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash32> OP_EQUAL */
void tapscript_build_hashlock(tapscript_leaf_t *leaf,
                               const unsigned char *hash32);

/* Build CLTV timeout script: <locktime> OP_CLTV OP_DROP <L_pubkey> OP_CHECKSIG */
int tapscript_build_cltv_timeout(
    tapscript_leaf_t *leaf,
    uint32_t locktime,
    const secp256k1_xonly_pubkey *lsp_pubkey,
    const secp256k1_context *ctx
);

/* Build CSV delay script: <delay> OP_CSV OP_DROP <pubkey> OP_CHECKSIG */
int tapscript_build_csv_delay(
    tapscript_leaf_t *leaf,
    uint32_t delay,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_context *ctx
);

/* Compute TapLeaf hash for a populated leaf */
void tapscript_compute_leaf_hash(tapscript_leaf_t *leaf);

/* Compute merkle root from leaves (single leaf: root = leaf_hash).
   Returns 1 on success, 0 on error (e.g., n_leaves == 0). */
int tapscript_merkle_root(unsigned char *root_out32,
                          const tapscript_leaf_t *leaves, size_t n_leaves);

/* Tweak internal key with merkle root -> output key */
int tapscript_tweak_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root32
);

/* Build control block for script-path spend of a single-leaf tree */
int tapscript_build_control_block(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const secp256k1_context *ctx
);

/* BIP-341 script-path sighash (SIGHASH_DEFAULT) */
int compute_tapscript_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx, size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_spk, size_t prev_spk_len,
    uint64_t prev_amount, uint32_t nsequence,
    const tapscript_leaf_t *leaf
);

/* Build unsigned tx with custom nLockTime */
int build_unsigned_tx_locktime(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *input_txid,
    uint32_t input_vout,
    uint32_t nsequence,
    uint32_t nlocktime,
    const tx_output_t *outputs,
    size_t n_outputs
);

/* Finalize tx with script-path witness: [sig, script, control_block] */
int finalize_script_path_tx(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len
);

/* Build revocation checksig leaf: <revocation_xonly_key> OP_CHECKSIG */
int tapscript_build_revocation_checksig(
    tapscript_leaf_t *leaf,
    const secp256k1_xonly_pubkey *revocation_pubkey,
    const secp256k1_context *ctx);

/* --- HTLC script builders --- */

/* Offered HTLC success leaf (remote claims with preimage, no CSV):
   OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <remote_key> OP_CHECKSIG */
int tapscript_build_htlc_offered_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx);

/* Offered HTLC timeout leaf (local reclaims after CLTV + CSV):
   <cltv> OP_CLTV OP_DROP <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
int tapscript_build_htlc_offered_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx);

/* Received HTLC success leaf (local claims with preimage + CSV):
   OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
int tapscript_build_htlc_received_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx);

/* Received HTLC timeout leaf (remote reclaims after CLTV, no CSV):
   <cltv> OP_CLTV OP_DROP <remote_key> OP_CHECKSIG */
int tapscript_build_htlc_received_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx);

/* Build control block for script-path spend of a 2-leaf tree.
   out must be >= 65 bytes. Result: [leaf_version|parity] || internal_key(32) || sibling_hash(32) */
int tapscript_build_control_block_2leaf(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const tapscript_leaf_t *sibling_leaf,
    const secp256k1_context *ctx);

/* Finalize tx with script-path witness including preimage:
   [sig, preimage, script, control_block] (4 witness items) */
int finalize_script_path_tx_preimage(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *preimage, size_t preimage_len,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len);

/*
 * Compute the BIP 341 key-path sighash for SIGHASH_ALL|ANYONECANPAY (0x81).
 *
 * This variant only requires the CURRENT input's amount and scriptPubKey,
 * making it suitable for in-process signing without access to all UTXOs.
 *
 * unsigned_tx: legacy (non-segwit) serialization of the unsigned transaction
 * tx_len:      byte length
 * input_index: which input is being signed (0-based)
 * prev_spk/prev_spk_len: scriptPubKey of the UTXO being spent
 * prev_amount: satoshi value of the UTXO being spent
 * nsequence:   nSequence of the input being signed
 *
 * Returns 1 on success, 0 on error.
 */
int compute_keypath_sighash_anyonecanpay(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx, size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_spk, size_t prev_spk_len,
    uint64_t prev_amount,
    uint32_t nsequence
);

/* --- CTV (BIP-119) primitives --- */

/*
 * Compute BIP-119 DefaultCheckTemplateVerifyHash.
 *
 * For segwit/taproot inputs (the case for us), the scriptSigs field is
 * elided per BIP-119: it's only included if any input has a non-empty
 * scriptSig.  All SuperScalar TXs use witness-only inputs so this field
 * is always omitted.
 *
 * Serialization (84 bytes total, no scriptSigs):
 *   LE32(nVersion)         (4)
 *   LE32(nLockTime)        (4)
 *   LE32(input_count)      (4)
 *   sequences_hash         (32)
 *   LE32(output_count)     (4)
 *   outputs_hash           (32)
 *   LE32(input_index)      (4)
 *
 * TH = sha256(of the above).
 *
 * Inputs:
 *   sequences_hash: sha256(concat(LE32(nSequence_i) for each input)).
 *   outputs_hash:   sha256(concat(serialize(CTxOut_j) for each output)).
 *                   Each CTxOut serialization is LE64(amount) ||
 *                   varint(spk_len) || spk_bytes.
 *
 * The caller computes sequences_hash and outputs_hash from actual data.
 *
 * Returns 1 on success.
 */
int ctv_template_hash(
    int32_t version,
    uint32_t locktime,
    uint32_t input_count,
    const unsigned char sequences_hash[32],
    uint32_t output_count,
    const unsigned char outputs_hash[32],
    uint32_t input_index,
    unsigned char out_th[32]);

/*
 * Build the CTV tap-leaf script:  <32-byte TH> OP_CHECKTEMPLATEVERIFY.
 *
 * The resulting script is exactly 34 bytes:
 *   0x20      (OP_PUSHBYTES_32)
 *   TH        (32 bytes)
 *   0xb3      (OP_NOP4 / OP_CHECKTEMPLATEVERIFY)
 *
 * The leaf's leaf_hash is also computed and stored.
 *
 * Returns 1 on success.
 */
int tapscript_build_ctv(
    tapscript_leaf_t *leaf,
    const unsigned char th[32]);

/*
 * Build the factory funding-output scriptPubKey.
 *
 * Three modes:
 *
 *   Legacy (no CTV):  ctv_th=NULL, sweep_leaf=NULL
 *     → key-path-only P2TR, byte-identical to today's inline
 *       construction at tools/superscalar_lsp.c:3370-3391.
 *
 *   CTV escape only:  ctv_th!=NULL, sweep_leaf=NULL
 *     → P2TR with 1 tap leaf: <ctv_th> OP_CTV.
 *
 *   CTV escape + LSP sweep:  ctv_th!=NULL, sweep_leaf!=NULL
 *     → P2TR with 2 tap leaves: the CTV leaf and the sweep leaf.
 *
 * The output is a 34-byte P2TR script: OP_1 || PUSHBYTES_32 || tweaked_xonly.
 *
 * Returns 1 on success.
 */
int build_factory_funding_spk(
    const secp256k1_context *ctx,
    const musig_keyagg_t   *ka,
    const unsigned char    *ctv_th,
    const tapscript_leaf_t *sweep_leaf,
    unsigned char           spk_out34[34]);

#endif /* SUPERSCALAR_TAPSCRIPT_H */
