# tests_address_book.cmake -- Address Book test definitions

# get_address_display_name: Address Book -> Trusted Name -> RAW resolution
# and conflict detection.
add_eth_unit_test(test_address_name_lookup
  NO_GLOBALS
  APP_SOURCES
    ${APP_DIR}/address_name_lookup.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/address_book
    ${BOLOS_SDK}/app_features/address_book/include
  DEFS
    HAVE_ADDRESS_BOOK
  WRAPS
    get_trusted_name
    get_address_book_contact
)
