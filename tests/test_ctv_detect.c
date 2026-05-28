/*
 * test_ctv_detect.c — unit tests for CTV (BIP-119) node-capability
 * detection (superscalar-ctv fork).
 *
 * Exercises regtest_parse_ctv_status() — the pure parser over a
 * getdeploymentinfo JSON-result string — with mock payloads.  No live
 * node needed; this is the testable core of the --ctv-mode startup check.
 *
 * Why this matters: OP_CHECKTEMPLATEVERIFY is OP_NOP4 on non-upgraded
 * nodes (anyone-can-spend).  The parser must correctly distinguish
 * "active/enforced" from "signaling/defined/absent/unknown" so the LSP
 * can refuse to create covenant outputs against a node that won't
 * enforce them.
 */

#include "superscalar/regtest.h"
#include <stdio.h>
#include <string.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* active via the per-deployment "active": true boolean. */
int test_ctv_parse_active_boolean(void) {
    const char *j =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"type\":\"bip9\",\"active\":true,"
        "\"bip9\":{\"bit\":5,\"status\":\"active\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_ACTIVE,
           "active:true must map to REGTEST_CTV_ACTIVE");
    return 1;
}

/* Real Bitcoin Inquisition payload: type "heretical" (NOT bip9), with a
   top-level active:true and a "heretical" sub-object instead of "bip9".
   Captured live from a bitcoin-28.1-inq regtest node's getdeploymentinfo
   (see tools/test_ctv_node_detection.sh).  The top-level "active" boolean
   must drive the verdict regardless of the absent bip9 object — this is the
   shape --ctv-mode actually meets against a real CTV node. */
int test_ctv_parse_inquisition_heretical_active(void) {
    const char *j =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"type\":\"heretical\",\"height\":0,\"active\":true,"
        "\"heretical\":{\"binana-id\":\"BIN-2016-0119-000\","
        "\"start_time\":-1,\"timeout\":9223372036854775807,\"period\":144}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_ACTIVE,
           "Inquisition heretical active:true must map to REGTEST_CTV_ACTIVE");
    return 1;
}

/* signaling states: started + locked_in. */
int test_ctv_parse_signaling(void) {
    const char *started =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"active\":false,\"bip9\":{\"bit\":5,\"status\":\"started\"}}}}";
    ASSERT(regtest_parse_ctv_status(started) == REGTEST_CTV_SIGNALING,
           "status=started must map to SIGNALING");
    const char *locked =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"active\":false,\"bip9\":{\"bit\":5,\"status\":\"locked_in\"}}}}";
    ASSERT(regtest_parse_ctv_status(locked) == REGTEST_CTV_SIGNALING,
           "status=locked_in must map to SIGNALING");
    return 1;
}

/* defined: known but not started. */
int test_ctv_parse_defined(void) {
    const char *j =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"active\":false,\"bip9\":{\"bit\":5,\"status\":\"defined\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_DEFINED,
           "status=defined must map to DEFINED");
    return 1;
}

/* failed deployment is treated as absent (won't ever enforce). */
int test_ctv_parse_failed_is_absent(void) {
    const char *j =
        "{\"deployments\":{\"checktemplateverify\":{"
        "\"active\":false,\"bip9\":{\"bit\":5,\"status\":\"failed\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_ABSENT,
           "status=failed must map to ABSENT");
    return 1;
}

/* alternate deployment name "ctv". */
int test_ctv_parse_alt_name(void) {
    const char *j =
        "{\"deployments\":{\"ctv\":{"
        "\"active\":true,\"bip9\":{\"bit\":5,\"status\":\"active\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_ACTIVE,
           "deployment named 'ctv' must be recognized");
    return 1;
}

/* bit-5 fallback: deployment NOT named ctv/checktemplateverify, but
   carries a bip9 deployment on bit 5. */
int test_ctv_parse_bit5_fallback(void) {
    const char *j =
        "{\"deployments\":{\"some_other_name\":{"
        "\"active\":false,\"bip9\":{\"bit\":5,\"status\":\"started\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_SIGNALING,
           "bit-5 bip9 deployment must be detected via fallback");
    return 1;
}

/* deployments object present but no CTV anywhere → ABSENT (vanilla node). */
int test_ctv_parse_absent(void) {
    const char *j =
        "{\"deployments\":{\"csv\":{\"active\":true},"
        "\"segwit\":{\"active\":true},"
        "\"taproot\":{\"active\":true,\"bip9\":{\"bit\":2,\"status\":\"active\"}}}}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_ABSENT,
           "no CTV deployment must map to ABSENT");
    return 1;
}

/* no deployments object → UNKNOWN (node too old / errored call). */
int test_ctv_parse_no_deployments_is_unknown(void) {
    const char *j = "{\"hash\":\"abc\",\"height\":100}";
    ASSERT(regtest_parse_ctv_status(j) == REGTEST_CTV_UNKNOWN,
           "missing deployments object must map to UNKNOWN");
    return 1;
}

/* NULL + garbage inputs → UNKNOWN (never crash, never false-positive). */
int test_ctv_parse_null_and_garbage(void) {
    ASSERT(regtest_parse_ctv_status(NULL) == REGTEST_CTV_UNKNOWN,
           "NULL must map to UNKNOWN");
    ASSERT(regtest_parse_ctv_status("not json at all") == REGTEST_CTV_UNKNOWN,
           "unparseable input must map to UNKNOWN");
    ASSERT(regtest_parse_ctv_status("") == REGTEST_CTV_UNKNOWN,
           "empty string must map to UNKNOWN");
    return 1;
}

/* status-string helper round-trips to readable labels. */
int test_ctv_status_str(void) {
    ASSERT(strcmp(regtest_ctv_status_str(REGTEST_CTV_ACTIVE), "active") == 0, "active label");
    ASSERT(strcmp(regtest_ctv_status_str(REGTEST_CTV_SIGNALING), "signaling") == 0, "signaling label");
    ASSERT(strcmp(regtest_ctv_status_str(REGTEST_CTV_DEFINED), "defined") == 0, "defined label");
    ASSERT(strcmp(regtest_ctv_status_str(REGTEST_CTV_ABSENT), "absent") == 0, "absent label");
    ASSERT(strcmp(regtest_ctv_status_str(REGTEST_CTV_UNKNOWN), "unknown") == 0, "unknown label");
    return 1;
}
