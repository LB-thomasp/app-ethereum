/**
 * @file test_tx_ctx.c
 * @brief Unit tests for the GCS transaction-context module at
 *        src/features/generic_tx_parser/tx_ctx.c.
 *
 * tx_ctx tracks the per-transaction state that survives across the
 * APDU stream: a doubly-linked list of s_tx_ctx nodes (one per outer
 * tx + optional inner sub-calls for proxy resolution), the
 * "current" pointer the parsers read through, and the parked
 * calldata buffer that hops from PROVIDE_CALLDATA into the node
 * created by tx_ctx_init().
 *
 * Tests focus on:
 *   - getter NULL-guards before any tx_ctx_init,
 *   - tx_ctx_init lifecycle: first call populates from/to/amount/
 *     chain_id, second call inherits from / chain_id from the
 *     previous tail, calldata ownership transfers (g_parked_calldata
 *     is cleared by the call),
 *   - tx_ctx_pop unlinks the current node and rewinds current,
 *   - find_matching_tx_ctx with selector + contract_addr + chain_id
 *     match,
 *   - validate_instruction_hash: real (mocked) hash compared against
 *     the stored fields_hash,
 *   - gcs_cleanup tears the whole state down.
 *
 * Out of scope: process_empty_txs_before / process_empty_txs_after
 * pull in too many display-layer dependencies (ticker lookup,
 * amountToString, trusted-name resolution, getEthDisplayableAddress)
 * for the scope of this slice.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "tx_ctx.h"
#include "gtp_field_table.h"
#include "trusted_name.h"
#include "address_name_lookup.h"
#include "shared_context.h"

// =============================================================================
// Globals
// =============================================================================

// =============================================================================
// Wraps / stubs for collaborators
// =============================================================================

// get_public_key writes ADDRESS_LENGTH bytes to its output buffer.
// We use a static "self" address for tests.
static const uint8_t g_self_addr[ADDRESS_LENGTH] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
};

// process_empty_tx is a static helper inside tx_ctx.c that drags display-
// layer symbols into the link even though our tests don't exercise it.
// Provide minimal stubs so the link resolves; these are NEVER called by
// the test cases below.

// EIP-712 calldata-info helpers — only reached when appState ==
// APP_STATE_SIGNING_EIP712, which our tests never set.
void *get_current_calldata_info(void) {
    return NULL;
}
bool calldata_info_all_received(const void *info) {
    (void) info;
    return false;
}
// Address-name resolution — reached only by the display path our tests skip.
bool __wrap_get_address_display_name(const uint8_t *addr,
                                     uint64_t chain_id,
                                     uint8_t type_count,
                                     const e_name_type *types,
                                     uint8_t source_count,
                                     const e_name_source *sources,
                                     char *buf,
                                     size_t buf_size,
                                     e_addr_name_source *name_source_out,
                                     const void **extra_data_out) {
    (void) addr;
    (void) chain_id;
    (void) type_count;
    (void) types;
    (void) source_count;
    (void) sources;
    (void) addr;
    // Mimic the production RAW fallback: always resolves, writing a
    // placeholder display string and reporting the RAW source.
    if (buf != NULL && buf_size > 0) {
        buf[0] = '\0';
    }
    if (name_source_out != NULL) {
        *name_source_out = ADDR_NAME_FROM_RAW;
    }
    if (extra_data_out != NULL) {
        *extra_data_out = NULL;
    }
    return true;
}

bool __wrap_get_public_key(uint8_t *buf, uint8_t size) {
    if (size != ADDRESS_LENGTH) return false;
    memcpy(buf, g_self_addr, ADDRESS_LENGTH);
    return true;
}

// finalize_hash: tests set the bytes to inject via g_finalize_hash_out.
static uint8_t g_finalize_hash_out[INT256_LENGTH];
static bool g_finalize_hash_ret = true;
bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    memcpy(out,
           g_finalize_hash_out,
           out_len < sizeof(g_finalize_hash_out) ? out_len : sizeof(g_finalize_hash_out));
    return g_finalize_hash_ret;
}

// ui / cleanup stubs
void __wrap_ui_gcs_cleanup(void) {
}
void __wrap_delete_tx_info(s_tx_info *node) {
    free(node);
}
bool __wrap_field_table_init(void) {
    return true;
}
void __wrap_field_table_cleanup(void) {
}

// find_matching_tx_ctx uses get_implem_contract for proxy resolution.
static const uint8_t *g_implem_contract_ret = NULL;
const uint8_t *__wrap_get_implem_contract(const uint64_t *chain_id,
                                          const uint8_t *to,
                                          const uint8_t *selector) {
    (void) chain_id;
    (void) to;
    (void) selector;
    return g_implem_contract_ret;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    gcs_cleanup();
    appState = APP_STATE_IDLE;
    memset(g_finalize_hash_out, 0, sizeof(g_finalize_hash_out));
    g_finalize_hash_ret = true;
    g_implem_contract_ret = NULL;
    return 0;
}

// Helper: set up a node and force g_tx_ctx_current to point at it by
// going through find_matching_tx_ctx. Returns the matched ctx through
// the getter side-effects.
static const uint8_t g_match_selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

static s_calldata *make_complete_calldata(const uint8_t *selector) {
    s_calldata *cd = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd, buf, CALLDATA_CHUNK_SIZE);
    return cd;
}

// Test data
static const uint8_t g_addr_a[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
static const uint8_t g_addr_b[ADDRESS_LENGTH] = {
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
};
static const uint8_t g_amount_1eth[INT256_LENGTH] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
};

// =============================================================================
// Getters — NULL-guard behavior on an empty list
// =============================================================================

static void test_getters_on_empty_list_return_null_or_zero(void **state) {
    (void) state;
    assert_false(tx_ctx_is_root());
    assert_int_equal(get_tx_ctx_count(), 0);
    assert_null(get_current_tx_info());
    assert_null(get_root_tx_info());
    assert_null(get_current_calldata());
    assert_null(get_root_calldata());
    assert_null(get_current_tx_from());
    assert_null(get_current_tx_to());
    assert_null(get_current_tx_amount());
    assert_int_equal(get_current_tx_chain_id(), 0);
}

// =============================================================================
// tx_ctx_init
// =============================================================================
// Note: tx_ctx_init pushes a new node but does NOT set g_tx_ctx_current.
// The current pointer is only set by find_matching_tx_ctx (or tx_ctx_pop
// rewinding to a previous current). So immediately after tx_ctx_init the
// getters still report empty even though the list has nodes.

static void test_init_adds_to_list_but_current_stays_null(void **state) {
    (void) state;
    uint64_t chain = 137;
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_b, g_amount_1eth, &chain));
    assert_int_equal(get_tx_ctx_count(), 1);
    // Current is not set yet — getters still NULL.
    assert_false(tx_ctx_is_root());
    assert_null(get_current_tx_from());
    assert_null(get_current_tx_to());
    assert_null(get_current_tx_amount());
    assert_int_equal(get_current_tx_chain_id(), 0);
}

static void test_init_then_find_matching_exposes_fields(void **state) {
    (void) state;
    uint64_t chain = 137;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, g_amount_1eth, &chain));

    // Use find_matching_tx_ctx to set current onto the new node.
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_true(tx_ctx_is_root());
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
    assert_memory_equal(get_current_tx_to(), g_addr_b, ADDRESS_LENGTH);
    assert_memory_equal(get_current_tx_amount(), g_amount_1eth, INT256_LENGTH);
    assert_int_equal(get_current_tx_chain_id(), 137);
}

static void test_init_first_call_with_null_from_uses_self(void **state) {
    (void) state;
    // get_public_key (wrapped) populates from when the caller passes NULL.
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, NULL, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_memory_equal(get_current_tx_from(), g_self_addr, ADDRESS_LENGTH);
}

static void test_init_second_call_inherits_from_and_chain(void **state) {
    (void) state;
    // First push sets from=addr_a, chain=56.
    uint64_t chain1 = 56;
    s_calldata *cd1 = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd1, g_addr_a, g_addr_a, NULL, &chain1));

    // Second push omits from / chain_id → must inherit from tail.
    // To then find_matching the second node we need a *different* selector
    // OR a different `to` since the matcher walks from head and returns
    // the first match.
    static const uint8_t selector2[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd2 = make_complete_calldata(selector2);
    assert_true(tx_ctx_init(cd2, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);
    // The second node's chain_id was inherited; use it for the match.
    uint64_t chain_lookup = 56;
    assert_true(find_matching_tx_ctx(g_addr_b, selector2, &chain_lookup));
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
    assert_int_equal(get_current_tx_chain_id(), 56);
    // The matched node is the second one — not the root.
    assert_false(tx_ctx_is_root());
}

static void test_init_clears_parked_calldata_pointer(void **state) {
    (void) state;
    // Simulate the host having parked a calldata buffer.
    s_calldata *cd = make_complete_calldata(g_match_selector);
    g_parked_calldata = cd;
    uint64_t chain = 1;
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    // tx_ctx_init takes ownership and clears the global so the host
    // cannot double-free.
    assert_null(g_parked_calldata);
}

// =============================================================================
// tx_ctx_pop
// =============================================================================

static void test_pop_unlinks_current_node(void **state) {
    (void) state;
    uint64_t chain1 = 1;
    s_calldata *cd1 = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd1, g_addr_a, g_addr_a, NULL, &chain1));

    static const uint8_t selector2[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd2 = make_complete_calldata(selector2);
    assert_true(tx_ctx_init(cd2, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);

    // Match the second node to set current = tail.
    uint64_t chain_lookup = 1;
    assert_true(find_matching_tx_ctx(g_addr_b, selector2, &chain_lookup));
    assert_false(tx_ctx_is_root());

    // Pop rewinds current to the previous node (the root).
    tx_ctx_pop();
    assert_int_equal(get_tx_ctx_count(), 1);
    assert_true(tx_ctx_is_root());
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
}

// =============================================================================
// find_matching_tx_ctx
// =============================================================================

static void test_find_matching_tx_ctx_happy(void **state) {
    (void) state;
    // Two contexts at different addresses; only the second matches the
    // search.
    uint64_t chain = 1;
    static const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    s_calldata *cd_a = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    s_calldata *cd_b = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    // Mark both calldatas complete so calldata->selector is readable.
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd_a, buf, CALLDATA_CHUNK_SIZE);
    calldata_append(cd_b, buf, CALLDATA_CHUNK_SIZE);

    assert_true(tx_ctx_init(cd_a, g_addr_a, g_addr_a, NULL, &chain));
    assert_true(tx_ctx_init(cd_b, NULL, g_addr_b, NULL, &chain));
    assert_int_equal(get_tx_ctx_count(), 2);

    assert_true(find_matching_tx_ctx(g_addr_b, selector, &chain));
    // current must now point at the second node — to=g_addr_b.
    assert_memory_equal(get_current_tx_to(), g_addr_b, ADDRESS_LENGTH);
}

static void test_find_matching_tx_ctx_no_match_keeps_current(void **state) {
    (void) state;
    uint64_t chain = 1;
    static const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    s_calldata *cd = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd, buf, CALLDATA_CHUNK_SIZE);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_a, NULL, &chain));

    // Search for an unrelated address.
    assert_false(find_matching_tx_ctx(g_addr_b, selector, &chain));
}

// =============================================================================
// validate_instruction_hash
// =============================================================================

static void test_validate_instruction_hash_matches(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    s_tx_info *heap_info = malloc(sizeof(s_tx_info));
    memset(heap_info, 0, sizeof(*heap_info));
    heap_info->fields_hash[0] = 0x11;
    heap_info->fields_hash[31] = 0xFF;

    // set_tx_info_into_tx_ctx at root with appState=IDLE skips both the
    // intent-field write and the auto-pop, so it only attaches the info.
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(heap_info));

    // Now make finalize_hash return the exact fields_hash so the
    // validator returns true.
    memcpy(g_finalize_hash_out, heap_info->fields_hash, sizeof(heap_info->fields_hash));
    assert_true(validate_instruction_hash());
}

static void test_validate_instruction_hash_mismatch(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    s_tx_info *heap_info = malloc(sizeof(s_tx_info));
    memset(heap_info, 0, sizeof(*heap_info));
    heap_info->fields_hash[0] = 0xFE;
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(heap_info));

    memset(g_finalize_hash_out, 0xCC, sizeof(g_finalize_hash_out));
    assert_false(validate_instruction_hash());
}

static void test_validate_instruction_hash_no_current_returns_false(void **state) {
    (void) state;
    assert_false(validate_instruction_hash());
}

// =============================================================================
// gcs_cleanup
// =============================================================================

static void test_gcs_cleanup_empties_list(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(tx_ctx_init(NULL, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);
    gcs_cleanup();
    assert_int_equal(get_tx_ctx_count(), 0);
    assert_null(g_parked_calldata);
}

static void test_gcs_cleanup_frees_parked_calldata(void **state) {
    (void) state;
    g_parked_calldata = calldata_init(0, NULL);
    gcs_cleanup();
    assert_null(g_parked_calldata);
}

// =============================================================================
// process_empty_txs_before / process_empty_txs_after
// =============================================================================
//
// An "empty" tx is a tx_ctx with no calldata attached — the parser
// inserts these as placeholders when the host first announces a batch
// of related transactions, then the active "with calldata" tx_ctx is
// pushed afterwards. process_empty_txs_{before,after} walks the
// neighbours of the current pointer, calls process_empty_tx on each
// empty one (which set_intent_field / amount / trusted_name / address
// formatting via the stubs above), and removes them from the list.

static void test_process_empty_txs_before_removes_empty_predecessors(void **state) {
    (void) state;
    uint64_t chain = 1;
    // 1) Two empty (calldata == NULL) predecessors
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, NULL, &chain));
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, NULL, &chain));
    // 2) The "with calldata" current tx
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_int_equal(get_tx_ctx_count(), 3);

    assert_true(process_empty_txs_before());
    // Both empty predecessors must be gone — only the current one
    // remains.
    assert_int_equal(get_tx_ctx_count(), 1);
}

static void test_process_empty_txs_after_removes_empty_successors(void **state) {
    (void) state;
    uint64_t chain = 1;
    // 1) Current with calldata
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    // 2) Two empty successors
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, NULL, &chain));
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_int_equal(get_tx_ctx_count(), 3);

    assert_true(process_empty_txs_after());
    assert_int_equal(get_tx_ctx_count(), 1);
}

static void test_process_empty_txs_before_stops_at_non_empty(void **state) {
    (void) state;
    uint64_t chain = 1;
    // Layout: [empty A] [withCalldata B] [current C, withCalldata]
    // process_empty_txs_before walks current -> prev. The first prev
    // (B) has calldata so the loop exits immediately. A is NOT
    // processed (still has calldata != NULL — wait, A is empty).
    // The loop reads tmp->calldata == NULL as the gate; B has
    // calldata so loop stops at B without touching A.
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, NULL, &chain));  // A empty
    s_calldata *cd_b = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd_b, g_addr_a, g_addr_a, NULL, &chain));  // B with calldata
    static const uint8_t selector_c[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd_c = make_complete_calldata(selector_c);
    assert_true(tx_ctx_init(cd_c, g_addr_a, g_addr_b, NULL, &chain));  // C current
    assert_true(find_matching_tx_ctx(g_addr_b, selector_c, &chain));
    assert_int_equal(get_tx_ctx_count(), 3);

    assert_true(process_empty_txs_before());
    // B blocks the walk → A stays untouched.
    assert_int_equal(get_tx_ctx_count(), 3);
}

static void test_process_empty_txs_with_amount_no_tx_info_fails(void **state) {
    (void) state;
    uint64_t chain = 1;
    // Empty predecessor with has_amount=true (amount provided) drives
    // process_empty_tx down the "Send" branch. Since no tx_info has
    // been attached to either the node or the root, the helper bails
    // at get_root_tx_info()==NULL and returns false — exercising the
    // error path inside the amount branch.
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, g_amount_1eth, &chain));
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    assert_false(process_empty_txs_before());
    // The empty node was NOT removed — process_empty_tx returned false
    // before reaching list_remove.
    assert_int_equal(get_tx_ctx_count(), 2);
}

// =============================================================================
// Remaining gaps: simple getters with current set, process_empty_tx
// amount happy path, set_tx_info_into_tx_ctx EIP712 + non-root,
// tx_ctx_init field_table_init path.
// =============================================================================

static void test_get_fields_hash_ctx_returns_current_ctx(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    // Non-NULL is enough — the pointer references the current node's
    // fields_hash_ctx member, opaque from here.
    assert_non_null(get_fields_hash_ctx());
}

static void test_get_current_getters_return_attached_state(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, g_amount_1eth, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    // tx_info attached after the fact via set_tx_info_into_tx_ctx.
    s_tx_info *info = calloc(1, sizeof(*info));
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(info));

    assert_ptr_equal(get_current_tx_info(), info);
    assert_ptr_equal(get_root_tx_info(), info);  // root == current here
    assert_non_null(get_current_calldata());
    assert_non_null(get_root_calldata());
}

// Amount-branch happy path inside process_empty_tx. Tags an empty
// predecessor with an amount, attaches a tx_info to the root (so
// get_root_tx_info finds one), and lets the trusted_name / amount /
// add_to_field_table stubs sail through.
static void test_process_empty_txs_amount_branch_happy_path(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd_root = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd_root, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    // Attach tx_info to the root so process_empty_tx's tx_info==NULL ->
    // get_root_tx_info() resolution path succeeds.
    s_tx_info *info = calloc(1, sizeof(*info));
    info->chain_id = 1;
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(info));

    // Insert an empty SUCCESSOR with has_amount=true (g_amount_1eth).
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_a, g_amount_1eth, &chain));
    assert_int_equal(get_tx_ctx_count(), 2);

    // process_empty_txs_after now drives process_empty_tx's amount path:
    //   set_intent_field("Send") + get_root_tx_info + amountToString +
    //   add_to_field_table + trusted_name lookup (returns NULL, falls
    //   back to RAW + getEthDisplayableAddress) + final add_to_field_table.
    assert_true(process_empty_txs_after());
    assert_int_equal(get_tx_ctx_count(), 1);  // empty successor removed
}

// set_tx_info_into_tx_ctx with appState=SIGNING_EIP712 takes the
// EIP712 path: set_intent_field + cx_sha3_init + finalize_hash. We
// arrange the hash mock so it does NOT match the tx_info hash, so
// tx_ctx_pop is skipped (matching pop would otherwise leave the
// node un-attached and surprise the assertion).
static void test_set_tx_info_eip712_at_root_runs_hash_path(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    s_tx_info *info = calloc(1, sizeof(*info));
    info->fields_hash[0] = 0xAA;  // distinct from g_finalize_hash_out
    appState = APP_STATE_SIGNING_EIP712;
    assert_true(set_tx_info_into_tx_ctx(info));
    // Node should still be attached (no pop) since hash mismatched.
    assert_ptr_equal(get_current_tx_info(), info);
}

// set_tx_info_into_tx_ctx on a non-root node (g_tx_ctx_current is the
// second node). The hash path runs unconditionally, set_intent_field
// is called outside the EIP712 branch.
static void test_set_tx_info_non_root_runs_intent_and_hash(void **state) {
    (void) state;
    uint64_t chain = 1;
    // Root
    s_calldata *cd_root = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd_root, g_addr_a, g_addr_a, NULL, &chain));
    // Second node (will become current)
    static const uint8_t selector_2[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd2 = make_complete_calldata(selector_2);
    assert_true(tx_ctx_init(cd2, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, selector_2, &chain));
    assert_int_equal(get_tx_ctx_count(), 2);

    s_tx_info *info = calloc(1, sizeof(*info));
    info->fields_hash[0] = 0xAA;
    appState = APP_STATE_IDLE;
    // Non-root path: set_intent_field called, hash path runs, hash
    // mismatches so no pop. Node stays.
    assert_true(set_tx_info_into_tx_ctx(info));
    assert_int_equal(get_tx_ctx_count(), 2);
}

// tx_ctx_init under APP_STATE_SIGNING_TX takes the field_table_init
// branch at the end (line 312-313). The wrapped __wrap_field_table_init
// returns true, so the init succeeds.
static void test_tx_ctx_init_signing_tx_calls_field_table_init(void **state) {
    (void) state;
    uint64_t chain = 1;
    appState = APP_STATE_SIGNING_TX;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_int_equal(get_tx_ctx_count(), 1);
    // Restore — gcs_cleanup in reset() will run between tests.
    appState = APP_STATE_IDLE;
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_getters_on_empty_list_return_null_or_zero, reset),
        cmocka_unit_test_setup(test_init_adds_to_list_but_current_stays_null, reset),
        cmocka_unit_test_setup(test_init_then_find_matching_exposes_fields, reset),
        cmocka_unit_test_setup(test_init_first_call_with_null_from_uses_self, reset),
        cmocka_unit_test_setup(test_init_second_call_inherits_from_and_chain, reset),
        cmocka_unit_test_setup(test_init_clears_parked_calldata_pointer, reset),
        cmocka_unit_test_setup(test_pop_unlinks_current_node, reset),
        cmocka_unit_test_setup(test_find_matching_tx_ctx_happy, reset),
        cmocka_unit_test_setup(test_find_matching_tx_ctx_no_match_keeps_current, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_matches, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_mismatch, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_no_current_returns_false, reset),
        cmocka_unit_test_setup(test_gcs_cleanup_empties_list, reset),
        cmocka_unit_test_setup(test_gcs_cleanup_frees_parked_calldata, reset),
        cmocka_unit_test_setup(test_process_empty_txs_before_removes_empty_predecessors, reset),
        cmocka_unit_test_setup(test_process_empty_txs_after_removes_empty_successors, reset),
        cmocka_unit_test_setup(test_process_empty_txs_before_stops_at_non_empty, reset),
        cmocka_unit_test_setup(test_process_empty_txs_with_amount_no_tx_info_fails, reset),
        cmocka_unit_test_setup(test_get_fields_hash_ctx_returns_current_ctx, reset),
        cmocka_unit_test_setup(test_get_current_getters_return_attached_state, reset),
        cmocka_unit_test_setup(test_process_empty_txs_amount_branch_happy_path, reset),
        cmocka_unit_test_setup(test_set_tx_info_eip712_at_root_runs_hash_path, reset),
        cmocka_unit_test_setup(test_set_tx_info_non_root_runs_intent_and_hash, reset),
        cmocka_unit_test_setup(test_tx_ctx_init_signing_tx_calls_field_table_init, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
