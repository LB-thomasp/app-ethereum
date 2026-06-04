/**
 * @file test_address_name_lookup.c
 * @brief Unit tests for get_address_display_name (Address Book→Trusted Name→RAW resolution)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "address_name_lookup.h"
#include "handle_contacts.h"
#include "shared_context.h"

#include "os.h"

strings_t strings;

static chain_config_t chainConfig_storage = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &chainConfig_storage;

// =============================================================================
// Controllable mocks
// =============================================================================

const s_trusted_name *__wrap_get_trusted_name(uint8_t type_count,
                                              const e_name_type *types,
                                              uint8_t source_count,
                                              const e_name_source *sources,
                                              const uint64_t *chain_id,
                                              const uint8_t *addr) {
    (void) type_count;
    (void) types;
    (void) source_count;
    (void) sources;
    (void) chain_id;
    (void) addr;
    return (const s_trusted_name *) mock();
}

const s_ab_contact *__wrap_get_address_book_contact(uint64_t chain_id, const uint8_t *addr) {
    (void) chain_id;
    (void) addr;
    return (const s_ab_contact *) mock();
}

// =============================================================================
// Test helpers
// =============================================================================

// clang-format off
static const uint8_t TEST_ADDR[ADDRESS_LENGTH] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44
};
// clang-format on

static const e_name_type TYPES_ACCOUNT[] = {TN_TYPE_ACCOUNT};
static const e_name_source SOURCES_ENS[] = {TN_SOURCE_ENS};
static const uint64_t CHAIN_ID = 1;

// =============================================================================
// Test cases
// =============================================================================

/**
 * Both Address Book and Trusted Name exist for the same address → Address Book wins, rendering
 * handles Trusted Name separately
 */
static void test_conflict_ab_and_tn(void **state) {
    (void) state;

    static s_ab_contact ab = {.contact_name = "Alice"};
    static s_trusted_name tn = {.name = "alice.eth"};
    char buf[64];
    e_addr_name_source name_source;
    const void *extra_data = NULL;

    will_return(__wrap_get_trusted_name, &tn);
    will_return(__wrap_get_address_book_contact, &ab);

    assert_true(get_address_display_name(TEST_ADDR,
                                         CHAIN_ID,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         &extra_data));

    assert_int_equal(name_source, ADDR_NAME_FROM_ADDRESS_BOOK);
    assert_string_equal(buf, "Alice");
    assert_ptr_equal(extra_data, &ab);
}

/**
 * Address Book contact found, no Trusted Name → ADDR_NAME_FROM_ADDRESS_BOOK, contact name in buf
 */
static void test_ab_only(void **state) {
    (void) state;

    static s_ab_contact ab = {.contact_name = "Alice"};
    char buf[64];
    e_addr_name_source name_source;
    const void *extra_data = NULL;

    will_return(__wrap_get_trusted_name, NULL);
    will_return(__wrap_get_address_book_contact, &ab);

    assert_true(get_address_display_name(TEST_ADDR,
                                         CHAIN_ID,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         &extra_data));

    assert_int_equal(name_source, ADDR_NAME_FROM_ADDRESS_BOOK);
    assert_string_equal(buf, "Alice");
    assert_ptr_equal(extra_data, &ab);
}

/**
 * No Address Book contact, Trusted Name found → ADDR_NAME_FROM_TRUSTED_NAME, tn name in buf
 */
static void test_tn_only(void **state) {
    (void) state;

    static s_trusted_name tn = {.name = "alice.eth"};
    char buf[64];
    e_addr_name_source name_source;
    const void *extra_data = NULL;

    will_return(__wrap_get_trusted_name, &tn);
    will_return(__wrap_get_address_book_contact, NULL);

    assert_true(get_address_display_name(TEST_ADDR,
                                         CHAIN_ID,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         &extra_data));

    assert_int_equal(name_source, ADDR_NAME_FROM_TRUSTED_NAME);
    assert_string_equal(buf, "alice.eth");
    assert_ptr_equal(extra_data, &tn);
}

/**
 * Neither Address Book nor Trusted Name found → ADDR_NAME_FROM_RAW, formatted address in buf
 */
static void test_raw_fallback(void **state) {
    (void) state;

    char buf[64];
    e_addr_name_source name_source;

    will_return(__wrap_get_trusted_name, NULL);
    will_return(__wrap_get_address_book_contact, NULL);

    assert_true(get_address_display_name(TEST_ADDR,
                                         CHAIN_ID,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         NULL));

    assert_int_equal(name_source, ADDR_NAME_FROM_RAW);
    assert_string_equal(buf, "0x11223344556677889900aabbccddeEfF11223344");
}

/**
 * TN_TYPE_ACCOUNT not in types → Address Book is not checked; Trusted Name found →
 * ADDR_NAME_FROM_TRUSTED_NAME
 */
static void test_non_account_type_skips_ab(void **state) {
    (void) state;

    static const e_name_type types_contract[] = {TN_TYPE_CONTRACT};
    static s_trusted_name tn = {.name = "MyContract"};
    char buf[64];
    e_addr_name_source name_source;

    will_return(__wrap_get_trusted_name, &tn);
    // get_address_book_contact must NOT be called (no will_return set for it)

    assert_true(get_address_display_name(TEST_ADDR,
                                         CHAIN_ID,
                                         1,
                                         types_contract,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         NULL));

    assert_int_equal(name_source, ADDR_NAME_FROM_TRUSTED_NAME);
    assert_string_equal(buf, "MyContract");
}

/**
 * Wrong chain_id (e.g. Polygon 137 instead of Ethereum 1): neither Address Book nor Trusted Name
 * resolves the address for a chain the entries were not registered on → RAW
 */
static void test_wrong_chain_id(void **state) {
    (void) state;

    const uint64_t polygon_chain_id = 137;
    char buf[64];
    e_addr_name_source name_source;

    // In the real implementation, get_trusted_name checks chain_id equality
    // and get_address_book_contact checks the contact's chain scope.
    // Both return NULL when the chain doesn't match.
    will_return(__wrap_get_trusted_name, NULL);
    will_return(__wrap_get_address_book_contact, NULL);

    assert_true(get_address_display_name(TEST_ADDR,
                                         polygon_chain_id,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         NULL));

    assert_int_equal(name_source, ADDR_NAME_FROM_RAW);
    assert_string_equal(buf, "0x11223344556677889900aabbccddeEfF11223344");
}

/**
 * Non-Ethereum blockchain family (chain_id=0): chain_is_ethereum_compatible
 * returns false inside get_trusted_name, so neither Address Book nor Trusted Name resolves → RAW
 */
static void test_non_ethereum_chain(void **state) {
    (void) state;

    const uint64_t non_eth_chain_id = 0;
    char buf[64];
    e_addr_name_source name_source;

    // In the real implementation, get_trusted_name rejects non-Ethereum-compatible
    // chains (chain_is_ethereum_compatible == false) and returns NULL.
    will_return(__wrap_get_trusted_name, NULL);
    will_return(__wrap_get_address_book_contact, NULL);

    assert_true(get_address_display_name(TEST_ADDR,
                                         non_eth_chain_id,
                                         1,
                                         TYPES_ACCOUNT,
                                         1,
                                         SOURCES_ENS,
                                         buf,
                                         sizeof(buf),
                                         &name_source,
                                         NULL));

    assert_int_equal(name_source, ADDR_NAME_FROM_RAW);
    assert_string_equal(buf, "0x11223344556677889900aabbccddeEfF11223344");
}

// =============================================================================
// Test runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_conflict_ab_and_tn),
        cmocka_unit_test(test_ab_only),
        cmocka_unit_test(test_tn_only),
        cmocka_unit_test(test_raw_fallback),
        cmocka_unit_test(test_non_account_type_skips_ab),
        cmocka_unit_test(test_wrong_chain_id),
        cmocka_unit_test(test_non_ethereum_chain),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
