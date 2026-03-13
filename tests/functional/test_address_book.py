# pylint: disable=too-many-lines
# Large test file containing multiple test cases and helper functions for the Address Book feature.
import hashlib
import hmac as hmac_module
import json
import struct
from pathlib import Path
from typing import Optional

from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.bip import pack_derivation_path
from ragger.bip.seed import SPECULOS_MNEMONIC
from ragger.navigator import NavInsID
from web3 import Web3

from test_eip712 import eip712_calldata_common, eip712_json_path, eip712_new_common, set_wallet_addr
from test_gcs import compute_inst_hash
from constants import ABIS_FOLDER
from fields_utils import get_all_tuple_array_paths, get_all_paths
from client.client import EthAppClient, SignMode
from client.gcs import (
    Field, ParamCalldata, ParamTrustedName, ParamTokenAmount,
    Value, TypeFamily, DataPath, ContainerPath, TxInfo,
)
from client.utils import get_selector_from_data, CoinType
from client.trusted_name import TrustedName, TrustedNameType, TrustedNameSource
import client.response_parser as ResponseParser
from client.status_word import StatusWord
from client.address_book import (
    AddressBookClient,
    AddressBookSubCommand,
    AddressBookResponseType,
    DEFAULT_BIP32_PATH,
    DEFAULT_CONTACT_NAME,
    DEFAULT_ADDRESS,
    DEFAULT_ACCOUNT_NAME,
    DEFAULT_SCOPE,
    DEFAULT_CHAIN_ID,
    GROUP_HANDLE_LENGTH,
    GID_SIZE,
    HMAC_PROOF_LENGTH,
)


# =============================================================================
# TX signing constants (shared across provide-contact tests)
# =============================================================================

NONCE     = 21
GAS_PRICE = 13
GAS_LIMIT = 21000
AMOUNT    = 1.22

# Secondary derivation path — used to register a Ledger Account whose address
# differs from the DEFAULT_BIP32_PATH signing account, so "From" and "To"
# show two distinct addresses in the TX review screen.
LEDGER_ACCOUNT_BIP32_PATH    = "m/44'/60'/0'/0/1"
SECONDARY_ACCOUNT_NAME       = "ETH secondary account"
SECONDARY_ADDRESS            = bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7")
SECONDARY_SCOPE              = "Eth Address 2"

# Max-length values (CONTACT_NAME_MAX_LENGTH == SCOPE_MAX_LENGTH == 32) used to
# validate long-name display (truncation / wrapping) on the device screens.
LONG_CONTACT_NAME = "Alice Very Long Contact Name 123"  # 32 chars
LONG_SCOPE        = "Ethereum Address Number One Long"  # 32 chars


# =============================================================================
# Constants (must match SDK address_book_crypto.c)
# =============================================================================

HMAC_KDF_SALT_IDENTITY       = b"AddressBook-Identity"
HMAC_KDF_SALT_LEDGER_ACCOUNT = b"AddressBook-LedgerAccount"
BLOCKCHAIN_FAMILY_ETHEREUM   = 1


# =============================================================================
# Crypto helpers
# =============================================================================

def bip32_path_to_list(path: str) -> list[int]:
    """Parse a BIP32 path string into a list of raw indices."""
    raw = pack_derivation_path(path)
    n = raw[0]
    return [struct.unpack('>I', raw[1 + i*4: 5 + i*4])[0] for i in range(n)]


def _derive_privkey(bip32_path: str) -> bytes:
    """Derive secp256k1 private key (SLIP-10) at the given BIP32 path."""
    seed_bytes = Bip39SeedGenerator(SPECULOS_MNEMONIC).Generate()
    ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    for level in bip32_path_to_list(bip32_path):
        ctx = ctx.ChildKey(level)
    return ctx.PrivateKey().Raw().ToBytes()


def derive_hmac_key_identity(bip32_path: str) -> bytes:
    """KDF for Identity HMAC: SHA256("AddressBook-Identity" || privkey.d)"""
    privkey_d = _derive_privkey(bip32_path)
    h = hashlib.sha256()
    h.update(HMAC_KDF_SALT_IDENTITY)
    h.update(privkey_d)
    return h.digest()


def derive_hmac_key_ledger_account(bip32_path: str) -> bytes:
    """KDF for Ledger Account HMAC: SHA256("AddressBook-LedgerAccount" || privkey.d)"""
    privkey_d = _derive_privkey(bip32_path)
    h = hashlib.sha256()
    h.update(HMAC_KDF_SALT_LEDGER_ACCOUNT)
    h.update(privkey_d)
    return h.digest()


def compute_hmac_name(bip32_path: str,
                      gid: bytes,
                      contact_name: str) -> bytes:
    """Compute HMAC_NAME for an Identity contact.

    Mirrors address_book_compute_hmac_name() in C.
    Message: gid(32) | name_len(1) | name
    """
    assert len(gid) == GID_SIZE
    key        = derive_hmac_key_identity(bip32_path)
    name_bytes = contact_name.encode('utf-8')
    msg = gid + bytes([len(name_bytes)]) + name_bytes
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def compute_hmac_rest(bip32_path: str,
                      gid: bytes,
                      scope: str,
                      address: bytes,
                      chain_id: int) -> bytes:
    """Compute HMAC_REST for an Identity contact.

    Mirrors address_book_compute_hmac_rest() in C.
    Message: gid(32) | scope_len(1) | scope | id_len(1) | address |
             family(1) [| chain_id(8) for FAMILY_ETHEREUM]
    """
    assert len(gid) == GID_SIZE
    key         = derive_hmac_key_identity(bip32_path)
    scope_bytes = scope.encode('utf-8')
    msg = (gid +
           bytes([len(scope_bytes)]) + scope_bytes +
           bytes([len(address)])  + address  +
           bytes([BLOCKCHAIN_FAMILY_ETHEREUM]))
    msg += chain_id.to_bytes(8, 'big')
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def compute_hmac_proof_ledger_account(bip32_path: str,
                                      contact_name: str,
                                      chain_id: int) -> bytes:
    """Compute HMAC Proof of Registration for a Ledger Account.

    Mirrors address_book_compute_hmac_proof_ledger_account() in C.
    Message: name_len(1) | name | family(1) | chain_id(8)
    chain_id is always encoded as 8 bytes big-endian
    """
    key        = derive_hmac_key_ledger_account(bip32_path)
    name_bytes = contact_name.encode('utf-8')
    chain_id = chain_id.to_bytes(8, 'big')
    msg = bytes([len(name_bytes)]) + name_bytes + bytes([BLOCKCHAIN_FAMILY_ETHEREUM]) + chain_id
    return hmac_module.new(key, msg, hashlib.sha256).digest()


# =============================================================================
# Response checkers
# =============================================================================

def _check_response_generic(app_client: EthAppClient,
                            expected_type: AddressBookResponseType,
                            bip32_path: str = DEFAULT_BIP32_PATH,
                            # Identity-specific params
                            gid: Optional[bytes] = None,
                            contact_name: Optional[str] = None,
                            scope: Optional[str] = None,
                            address: Optional[bytes] = None,
                            chain_id: int = DEFAULT_CHAIN_ID) -> tuple:
    """Generic response verifier for all Address Book response types.

    Returns (formats by type):
        - REGISTER_IDENTITY:        1 + 64 + 32 + 32 = 129B (group_handle + hmac_name + hmac_rest)
        - EDIT_CONTACT_NAME:        1 + 32            = 33B  (hmac_name, None, None)
        - EDIT_IDENTIFIER:          1 + 32            = 33B  (hmac_rest, None, None)
        - EDIT_SCOPE:               1 + 32            = 33B  (hmac_rest, None, None)
        - REGISTER_LEDGER_ACCOUNT:  1 + 32            = 33B  (hmac_proof, None, None)
        - EDIT_LEDGER_ACCOUNT:      1 + 32            = 33B  (hmac_proof, None, None)
    """
    response = app_client.response()
    assert response is not None, "No response received"
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    data = response.data

    # Verify type byte
    actual_type = data[0]
    assert actual_type == expected_type, \
        f"Unexpected response type: 0x{actual_type:02x}, expected {expected_type.name}"

    # -------------------------------------------------------------------------
    # REGISTER_IDENTITY: type(1) | group_handle(64) | hmac_name(32) | hmac_rest(32)
    # -------------------------------------------------------------------------
    if expected_type == AddressBookResponseType.TYPE_REGISTER_IDENTITY:
        expected_len = 1 + GROUP_HANDLE_LENGTH + HMAC_PROOF_LENGTH + HMAC_PROOF_LENGTH
        assert len(data) == expected_len, \
            f"Expected {expected_len} bytes for REGISTER_IDENTITY, got {len(data)}"

        group_handle = data[1:1 + GROUP_HANDLE_LENGTH]
        gid_from_response = group_handle[:GID_SIZE]  # first 32B of group_handle
        offset = 1 + GROUP_HANDLE_LENGTH

        assert contact_name is not None, "contact_name required for REGISTER_IDENTITY"
        assert scope is not None and address is not None, \
            "scope and address required for REGISTER_IDENTITY HMAC_REST"

        device_hmac_name = data[offset:offset + HMAC_PROOF_LENGTH]
        offset += HMAC_PROOF_LENGTH
        expected_hmac_name = compute_hmac_name(bip32_path, gid_from_response, contact_name)
        assert device_hmac_name == expected_hmac_name, (
            f"HMAC_NAME mismatch:\n"
            f"  device:   {device_hmac_name.hex()}\n"
            f"  expected: {expected_hmac_name.hex()}"
        )

        device_hmac_rest = data[offset:offset + HMAC_PROOF_LENGTH]
        expected_hmac_rest = compute_hmac_rest(bip32_path, gid_from_response, scope, address, chain_id)
        assert device_hmac_rest == expected_hmac_rest, (
            f"HMAC_REST mismatch:\n"
            f"  device:   {device_hmac_rest.hex()}\n"
            f"  expected: {expected_hmac_rest.hex()}"
        )

        return (group_handle, device_hmac_name, device_hmac_rest)

    # -------------------------------------------------------------------------
    # All other types: type(1) | hmac(32) = 33B
    # -------------------------------------------------------------------------
    expected_len = 1 + HMAC_PROOF_LENGTH
    assert len(data) == expected_len, \
        f"Expected {expected_len} bytes for {expected_type.name}, got {len(data)}"

    device_hmac = data[1:1 + HMAC_PROOF_LENGTH]

    if expected_type == AddressBookResponseType.TYPE_EDIT_CONTACT_NAME:
        assert gid is not None and contact_name is not None, \
            "gid and contact_name required for EDIT_CONTACT_NAME"
        expected_hmac = compute_hmac_name(bip32_path, gid, contact_name)
        assert device_hmac == expected_hmac, (
            f"HMAC_NAME mismatch:\n"
            f"  device:   {device_hmac.hex()}\n"
            f"  expected: {expected_hmac.hex()}"
        )

    elif expected_type in (AddressBookResponseType.TYPE_EDIT_IDENTIFIER,
                           AddressBookResponseType.TYPE_EDIT_SCOPE):
        assert all(p is not None for p in [gid, scope, address]), \
            "gid, scope, and address required for HMAC_REST"
        expected_hmac = compute_hmac_rest(bip32_path, gid, scope, address, chain_id)
        assert device_hmac == expected_hmac, (
            f"HMAC_REST mismatch:\n"
            f"  device:   {device_hmac.hex()}\n"
            f"  expected: {expected_hmac.hex()}"
        )

    elif expected_type in (AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT,
                           AddressBookResponseType.TYPE_EDIT_LEDGER_ACCOUNT):
        assert contact_name is not None, "contact_name required for Ledger Account HMAC"
        expected_hmac = compute_hmac_proof_ledger_account(bip32_path, contact_name, chain_id)
        assert device_hmac == expected_hmac, (
            f"HMAC_PROOF mismatch:\n"
            f"  device:   {device_hmac.hex()}\n"
            f"  expected: {expected_hmac.hex()}"
        )

    return (device_hmac, None, None)


def check_identity_response(app_client: EthAppClient,
                            contact_name: str,
                            scope: str,
                            address: bytes = DEFAULT_ADDRESS,
                            bip32_path: str = DEFAULT_BIP32_PATH,
                            chain_id: int = DEFAULT_CHAIN_ID) -> tuple[bytes, bytes, bytes]:
    """Verify the Register Identity response and return (group_handle, hmac_name, hmac_rest).

    group_handle (64B) must be stored by the wallet and re-sent in all subsequent
    Edit operations for this contact.
    """
    group_handle, hmac_name, hmac_rest = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_REGISTER_IDENTITY,
        bip32_path,
        contact_name=contact_name,
        scope=scope,
        address=address,
        chain_id=chain_id,
    )
    print("✓ Register Identity: group_handle, HMAC_NAME and HMAC_REST verified")
    return group_handle, hmac_name, hmac_rest


def check_ledger_account_response(app_client: EthAppClient,
                                  contact_name: str = DEFAULT_ACCOUNT_NAME,
                                  bip32_path: str = DEFAULT_BIP32_PATH,
                                  chain_id: int = DEFAULT_CHAIN_ID) -> bytes:
    """Verify the Register Ledger Account response and return the HMAC proof."""
    hmac_proof, _, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT,
        bip32_path,
        contact_name=contact_name,
        chain_id=chain_id,
    )
    print("✓ HMAC Proof of Registration (Ledger Account) verified")
    return hmac_proof


def check_edit_contact_name_response(app_client: EthAppClient,
                                     contact_name: str,
                                     group_handle: bytes,
                                     bip32_path: str = DEFAULT_BIP32_PATH) -> bytes:
    """Verify the Edit Contact Name response and return the new HMAC_NAME."""
    hmac_name, _, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_CONTACT_NAME,
        bip32_path,
        gid=group_handle[:GID_SIZE],
        contact_name=contact_name,
    )
    print("✓ Edit Contact Name: HMAC_NAME verified")
    return hmac_name


def check_edit_identifier_response(app_client: EthAppClient,
                                   address: bytes,
                                   group_handle: bytes,
                                   scope: str = DEFAULT_SCOPE,
                                   bip32_path: str = DEFAULT_BIP32_PATH,
                                   chain_id: int = DEFAULT_CHAIN_ID) -> bytes:
    """Verify the Edit Identifier response and return the new HMAC_REST."""
    hmac_rest, _, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_IDENTIFIER,
        bip32_path,
        gid=group_handle[:GID_SIZE],
        scope=scope,
        address=address,
        chain_id=chain_id,
    )
    print("✓ Edit Identifier: HMAC_REST verified")
    return hmac_rest


def check_edit_scope_response(app_client: EthAppClient,
                              scope: str,
                              group_handle: bytes,
                              address: bytes = DEFAULT_ADDRESS,
                              bip32_path: str = DEFAULT_BIP32_PATH,
                              chain_id: int = DEFAULT_CHAIN_ID) -> bytes:
    """Verify the Edit Scope response and return the new HMAC_REST."""
    hmac_rest, _, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_SCOPE,
        bip32_path,
        gid=group_handle[:GID_SIZE],
        scope=scope,
        address=address,
        chain_id=chain_id,
    )
    print("✓ Edit Scope: HMAC_REST verified")
    return hmac_rest


def check_edit_ledger_account_response(app_client: EthAppClient,
                                       contact_name: str,
                                       bip32_path: str = DEFAULT_BIP32_PATH,
                                       chain_id: int = DEFAULT_CHAIN_ID) -> bytes:
    """Verify the Edit Ledger Account response and return the new HMAC proof."""
    hmac_proof, _, _ = _check_response_generic(
        app_client,
        AddressBookResponseType.TYPE_EDIT_LEDGER_ACCOUNT,
        bip32_path,
        contact_name=contact_name,
        chain_id=chain_id,
    )
    print("✓ HMAC Proof of Registration (Edit Ledger Account) verified")
    return hmac_proof


# =============================================================================
# Test helpers
# =============================================================================

def assert_sw(actual: int, expected) -> None:
    """Assert a status word with hex display on failure."""
    assert actual == expected, f"StatusWord: Expected 0x{int(expected):04X}, got 0x{actual:04X}"


def _common_register_identity(scenario_navigator: NavigateWithScenario,
                              app_client: EthAppClient,
                              addr_book: AddressBookClient,
                              contact_name: str = DEFAULT_CONTACT_NAME,
                              scope: str = DEFAULT_SCOPE,
                              address: bytes = DEFAULT_ADDRESS,
                              do_compare: bool = True,
                              group_handle: Optional[bytes] = None,
                              hmac_proof: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
    """Common helper to register an Identity contact.

    Args:
        scenario_navigator: Test navigator
        app_client: Ethereum app client
        addr_book: Address book client
        contact_name: Contact name
        scope: Optional contact scope (address name)
        address: Address bytes (20 bytes for Ethereum)
        do_compare: If False, uses "/register" test suffix to skip snapshot comparison
        group_handle: Optional 64-byte group handle to link to an existing group
        hmac_proof: Required when group_handle is provided

    Returns:
        Tuple of (group_handle, hmac_name, hmac_rest).
        group_handle (64B) must be passed to all subsequent Edit operations.
    """
    apdu = addr_book.prepare_register_identity(
        address,
        contact_name,
        scope=scope,
        group_handle=group_handle,
        hmac_proof=hmac_proof,
    )

    with app_client.provide_address_book(addr_book,
                                         apdu,
                                         AddressBookSubCommand.SUB_CMD_REGISTER_IDENTITY):
        scenario_navigator.address_review_approve(do_comparison=do_compare, custom_screen_text="Confirm")

    return check_identity_response(app_client, contact_name, scope, address=address)


def _common_register_ledger_account(scenario_navigator: NavigateWithScenario,
                                    app_client: EthAppClient,
                                    addr_book: AddressBookClient,
                                    do_compare: bool = True,
                                    derivation_path: str = DEFAULT_BIP32_PATH,
                                    contact_name: str = DEFAULT_ACCOUNT_NAME) -> bytes:
    """Common helper to register a Ledger Account.

    Args:
        scenario_navigator: Test navigator
        app_client: Ethereum app client
        addr_book: Address book client
        do_compare: If False, uses "/register" test suffix to skip snapshot comparison
        derivation_path: BIP32 path to register; defaults to DEFAULT_BIP32_PATH
        contact_name: Human-readable name for the account; defaults to DEFAULT_ACCOUNT_NAME

    Returns:
        HMAC proof
    """
    apdu = addr_book.prepare_register_ledger_account(contact_name=contact_name,
                                                     derivation_path=derivation_path)

    instructions = []
    if scenario_navigator.backend.device.is_nano:
        instructions += [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ]
    else:
        instructions += [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.LEFT_HEADER_TAP,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        ]

    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_REGISTER_LEDGER_ACCOUNT):
        if do_compare:
            scenario_navigator.navigator.navigate_and_compare(scenario_navigator.screenshot_path,
                                                              scenario_navigator.test_name,
                                                              instructions)
        else:
            scenario_navigator.navigator.navigate(instructions)

    # Ensure we're back on the home screen to ensure the dynamic allocation are freed
    scenario_navigator.backend.wait_for_home_screen()

    return check_ledger_account_response(app_client, contact_name=contact_name,
                                         bip32_path=derivation_path)


# =============================================================================
# Identity Tests — Register
# =============================================================================

def test_address_book_identity_register(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Identity: bind a name + scope to an Ethereum address.

    Verifies that the device returns two valid HMACs (HMAC_NAME and HMAC_REST)
    that can be independently re-derived from the same inputs.
    """
    backend  = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    _common_register_identity(scenario_navigator, app_client, addr_book)


def test_address_book_identity_register_reject(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Identity: user rejects → ExceptionRAPDU(SWO_INCORRECT_DATA)."""
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    apdu = addr_book.prepare_register_identity(
        DEFAULT_ADDRESS, DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE,
    )
    text = "Cancel" if scenario_navigator.backend.device.is_nano else "Confirm"
    try:
        with app_client.provide_address_book(addr_book, apdu,
                                             AddressBookSubCommand.SUB_CMD_REGISTER_IDENTITY):
            scenario_navigator.review_reject(custom_screen_text=text)
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_INCORRECT_DATA)
    else:
        assert False, "Register Identity should have raised ExceptionRAPDU on user rejection"


def test_address_book_identity_register_long_name(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Identity with a max-length (32-char) name and scope.

    Captures dedicated snapshots to validate how the device renders a long
    contact name and scope (truncation / wrapping) on the Register Identity
    review screen, without changing the default short values used elsewhere.
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    _common_register_identity(
        scenario_navigator, app_client, addr_book,
        contact_name=LONG_CONTACT_NAME,
        scope=LONG_SCOPE,
    )


# =============================================================================
# Identity Tests — Edit Identifier
# =============================================================================

def test_address_book_identity_edit_identifier(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Identifier: change the address of an existing contact.

    Flow:
      1. Register Identity → receive (hmac_name, hmac_rest_old)
      2. Edit Identifier: address_old → address_new, providing hmac_rest_old
      3. Verify the returned new HMAC_REST covers (gid, scope, address_new)
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_address = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name_old, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Identifier (address_old → address_new)
    apdu = addr_book.prepare_edit_identifier(new_address, hmac_name_old, hmac_rest_old, group_handle)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_IDENTIFIER):
        scenario_navigator.address_review_approve(custom_screen_text="Confirm")
    check_edit_identifier_response(app_client, new_address, group_handle)


# =============================================================================
# Identity Tests — Edit Contact Name
# =============================================================================

def test_address_book_identity_edit_contact_name(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Contact Name: rename an existing contact.

    Flow:
      1. Register Identity → receive (hmac_name_old, hmac_rest)
      2. Edit Contact Name, providing group_handle + hmac_name_old
         (no address, scope, or network needed)
      3. Verify the returned HMAC_NAME covers (gid, "Bob")
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "Bob"

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name_old, _ = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Contact Name (Alice → Bob)
    apdu = addr_book.prepare_edit_contact_name(DEFAULT_CONTACT_NAME, new_name, hmac_name_old, group_handle)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME):
        scenario_navigator.address_review_approve(custom_screen_text="Confirm")
    check_edit_contact_name_response(app_client, new_name, group_handle)


def test_address_book_identity_edit_contact_name_reject(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Contact Name: user rejects → ExceptionRAPDU(SWO_INCORRECT_DATA).

    Flow:
      1. Register Identity → receive (group_handle, hmac_name_old)
      2. Edit Contact Name → user rejects at review screen
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "Bob"

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name_old, _ = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Contact Name → user rejects
    apdu = addr_book.prepare_edit_contact_name(DEFAULT_CONTACT_NAME, new_name,
                                               hmac_name_old, group_handle)

    text = "Cancel" if scenario_navigator.backend.device.is_nano else "Confirm"
    try:
        with app_client.provide_address_book(addr_book, apdu,
                                             AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME):
            scenario_navigator.review_reject(custom_screen_text=text)
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_INCORRECT_DATA)
    else:
        assert False, "Edit Contact Name should have raised ExceptionRAPDU on user rejection"


# =============================================================================
# Identity Tests — Edit Scope
# =============================================================================

def test_address_book_identity_edit_scope(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Scope: change the scope of an existing contact.

    Flow:
      1. Register Identity
         → receive (hmac_name, hmac_rest_old)
      2. Edit Scope, providing hmac_rest_old
      3. Verify the returned HMAC_REST covers (gid, "Eth Savings", address, ...)
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_scope = "Eth Savings"

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name_old, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Scope
    apdu = addr_book.prepare_edit_scope(
        DEFAULT_SCOPE, new_scope, hmac_name_old, hmac_rest_old, group_handle
    )
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_SCOPE):
        scenario_navigator.address_review_approve(custom_screen_text="Confirm")
    check_edit_scope_response(app_client, new_scope, group_handle)


# =============================================================================
# Ledger Account Tests — Register
# =============================================================================

def test_address_book_ledger_account_register(scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Ledger Account: bind a name to a BIP32 derivation path."""
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    _common_register_ledger_account(scenario_navigator, app_client, addr_book)


def test_address_book_ledger_account_register_reject(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Register Ledger Account: user rejects → ExceptionRAPDU(SWO_INCORRECT_DATA)."""
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    apdu = addr_book.prepare_register_ledger_account()

    if scenario_navigator.backend.device.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,  # navigate past Confirm to Reject
            NavInsID.BOTH_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.LEFT_HEADER_TAP,
            NavInsID.USE_CASE_CHOICE_REJECT,
        ]

    try:
        with app_client.provide_address_book(addr_book, apdu,
                                             AddressBookSubCommand.SUB_CMD_REGISTER_LEDGER_ACCOUNT):
            scenario_navigator.navigator.navigate(instructions)
    except ExceptionRAPDU as e:
        # Ensure we're back on the home screen to ensure the dynamic allocation are freed
        scenario_navigator.backend.wait_for_home_screen()
        assert_sw(e.status, StatusWord.SWO_INCORRECT_DATA)
    else:
        assert False, "Register Ledger Account should have raised ExceptionRAPDU on user rejection"


# =============================================================================
# Ledger Account Tests — Edit
# =============================================================================

def test_address_book_ledger_account_edit(scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Ledger Account: rename an existing account.

    Flow:
      1. Register Ledger Account "ETH main address" → receive hmac_proof_old
      2. Rename → "ETH savings", providing hmac_proof_old
      3. Verify the new HMAC proof matches the proof for "ETH savings"
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "ETH savings"

    # Step 1: Register Ledger Account (skip snapshot comparison)
    hmac_proof_old = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book, do_compare=False,
    )

    # Step 2: Edit Ledger Account
    apdu = addr_book.prepare_edit_ledger_account(new_name, hmac_proof_old)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_LEDGER_ACCOUNT):
        scenario_navigator.address_review_approve(custom_screen_text="Confirm")
    check_edit_ledger_account_response(app_client, new_name)


def test_address_book_ledger_account_edit_reject(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Edit Ledger Account: user rejects → ExceptionRAPDU(SWO_INCORRECT_DATA).

    Flow:
      1. Register Ledger Account → receive hmac_proof_old
      2. Edit Ledger Account → user rejects at review screen
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "ETH savings"

    # Step 1: Register Ledger Account (skip snapshot comparison)
    hmac_proof_old = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book, do_compare=False,
    )

    # Step 2: Edit Ledger Account → user rejects
    apdu = addr_book.prepare_edit_ledger_account(new_name, hmac_proof_old)

    text = "Cancel" if scenario_navigator.backend.device.is_nano else "Confirm"
    try:
        with app_client.provide_address_book(addr_book, apdu,
                                            AddressBookSubCommand.SUB_CMD_EDIT_LEDGER_ACCOUNT):
            scenario_navigator.review_reject(custom_screen_text=text)
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_INCORRECT_DATA)
    else:
        assert False, "Edit Ledger Account should have raised ExceptionRAPDU on user rejection"


# =============================================================================
# Provide Contact Tests with Tx Review
# =============================================================================

def test_address_book_simple_tx(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact name replaces raw address in TX review.

    Flow:
      1. Register Identity (no screenshot comparison)
         → receive (group_handle, hmac_name, hmac_rest)
      2. Provide Contact (synchronous, no UI)
         → device stores the contact and responds 9000 with no data
      3. Sign a TX to the same address
         → "To" field shows the contact name instead of the raw address
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS,
        group_handle,
        hmac_name,
        hmac_rest,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0, \
        f"Provide Contact must return no data, got {response.data.hex()}"

    # Step 3: Sign TX to the same address — contact name shown in review
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_simple_tx_long_name(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: a max-length (32-char) contact name in the TX "To" field.

    Same flow as test_address_book_simple_tx but with a 32-char contact name +
    scope, to validate how the long name is rendered (truncation / wrapping) in
    the "To" field of the transaction review screen.

    Flow:
      1. Register Identity with LONG_CONTACT_NAME / LONG_SCOPE (no comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign a TX to the same address → "To" shows the long contact name
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    # Step 1: Register Identity with the long name / scope
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        contact_name=LONG_CONTACT_NAME,
        scope=LONG_SCOPE,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS,
        group_handle,
        hmac_name,
        hmac_rest,
        contact_name=LONG_CONTACT_NAME,
        scope=LONG_SCOPE,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0, \
        f"Provide Contact must return no data, got {response.data.hex()}"

    # Step 3: Sign TX to the same address — "To" shows the long contact name
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_simple_tx_reject(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: user rejects the TX after the contact name is shown.

    Flow:
      1. Register Identity (no screenshot comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign a TX to the same address → user rejects at the review screen
         → ExceptionRAPDU with CONDITION_NOT_SATISFIED
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(DEFAULT_ADDRESS, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign TX — user rejects at review
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    try:
        with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
            scenario_navigator.review_reject()
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_CONDITIONS_NOT_SATISFIED)
    else:
        assert False, "Signing should have raised ExceptionRAPDU on user rejection"


def test_address_book_simple_tx_chain_id_mismatch(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact stored for chain A is not resolved when signing on chain B.

    A contact is registered and provided for DEFAULT_CHAIN_ID=1 (Ethereum mainnet).
    A TX is then signed on a different chain (Polygon, 137). get_address_book_contact(137,
    addr) returns NULL because the stored chain_id does not match, so the raw address must
    be shown.

    Flow:
      1. Register Identity for DEFAULT_CHAIN_ID=1 (no screenshot comparison)
      2. Provide Contact for chain_id=1 (stored in device memory)
      3. Sign a TX on chain_id=137 to the same address
         → get_address_book_contact(137, addr) == NULL → raw address shown
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)
    wrong_chain_id = 137  # Polygon

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Contact for chain_id=1 (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS,
        group_handle,
        hmac_name,
        hmac_rest,
        chain_id=DEFAULT_CHAIN_ID,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign TX on chain_id=137 — stored contact has chain_id=1, so no match → raw
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": wrong_chain_id,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_multi_address(scenario_navigator: NavigateWithScenario) -> None:
    """Test that renaming a contact propagates to all addresses in the same group.

    Register Identity can be called with an existing group_handle + hmac_proof
    to link a second address to an existing group (same GID, hence same HMAC key).
    Both addresses share the contact name; after a rename, both must display the new
    name in TX reviews.

    Flow:
      1. Register Identity for DEFAULT_ADDRESS              → (group_handle, hmac_name_alice, hmac_rest_1)
      2. Register Identity for SECONDARY_ADDRESS (same group) → (group_handle, hmac_name_alice, hmac_rest_2)
      3. Rename Alice → Bob                                 → hmac_name_bob
      4. Provide Contact for SECONDARY_ADDRESS (group_handle, hmac_name_bob, hmac_rest_2, "Bob")
      5. Sign TX to SECONDARY_ADDRESS → "To" shows "Bob"
      6. Provide Contact for DEFAULT_ADDRESS   (group_handle, hmac_name_bob, hmac_rest_1, "Bob")
      7. Sign TX to DEFAULT_ADDRESS   → "To" shows "Bob"
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "Bob"

    # Step 1: Register first address — creates a new group
    group_handle, hmac_name_alice, hmac_rest_1 = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Register second address under the same group
    group_handle_echo, hmac_name_echo, hmac_rest_2 = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=SECONDARY_ADDRESS,
        scope=SECONDARY_SCOPE,
        do_compare=False,
        group_handle=group_handle,
        hmac_proof=hmac_name_alice,
    )
    # The device echoes back the same group_handle and hmac_name
    assert group_handle_echo == group_handle
    assert hmac_name_echo == hmac_name_alice

    # Step 3: Rename Alice → Bob; hmac_name_alice is now invalid for Provide Contact
    apdu = addr_book.prepare_edit_contact_name(DEFAULT_CONTACT_NAME, new_name,
                                               hmac_name_alice, group_handle)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    hmac_name_bob = check_edit_contact_name_response(app_client, new_name, group_handle)

    # Step 4: Provide Contact for SECONDARY_ADDRESS with the new name
    apdu = addr_book.prepare_provide_contact(
        SECONDARY_ADDRESS, group_handle, hmac_name_bob, hmac_rest_2,
        contact_name=new_name,
        scope=SECONDARY_SCOPE,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)

    # Step 5: Sign TX to SECONDARY_ADDRESS — "To" must show "Bob"
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": SECONDARY_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    test_name = scenario_navigator.test_name
    if not backend.device.is_nano:
        test_name += "/step1"
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve(test_name=test_name)

    # Step 6: Provide Contact for DEFAULT_ADDRESS with the new name (contacts cleared after sign)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS, group_handle, hmac_name_bob, hmac_rest_1,
        contact_name=new_name,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)

    # Step 7: Sign TX to DEFAULT_ADDRESS — "To" must also show "Bob"
    tx_params["to"] = DEFAULT_ADDRESS
    if not backend.device.is_nano:
        test_name = test_name.replace("/step1", "/step2")
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve(test_name=test_name)


def test_address_book_simple_tx_ledger_account(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact from two Ledger Accounts: both From and To show account names.

    DEFAULT_BIP32_PATH is registered as DEFAULT_ACCOUNT_NAME (the signing account),
    so "From" shows the account name.  LEDGER_ACCOUNT_BIP32_PATH is registered as
    SECONDARY_ACCOUNT_NAME (the recipient), so "To" also shows a name.

    Flow:
      1. Register Ledger Account at DEFAULT_BIP32_PATH (From) → hmac_proof_from
      2. Provide Contact for DEFAULT_BIP32_PATH
      3. Register Ledger Account at LEDGER_ACCOUNT_BIP32_PATH (To) → hmac_proof_to
      4. Get the device address at LEDGER_ACCOUNT_BIP32_PATH (the TX recipient)
      5. Provide Contact for LEDGER_ACCOUNT_BIP32_PATH
      6. Sign a TX from DEFAULT_BIP32_PATH to that address
         → "From" shows DEFAULT_ACCOUNT_NAME, "To" shows SECONDARY_ACCOUNT_NAME
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    # Step 1: Register the signing (From) account
    hmac_proof_from = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
        derivation_path=DEFAULT_BIP32_PATH,
        contact_name=DEFAULT_ACCOUNT_NAME,
    )

    # Step 2: Provide Contact for the From account
    apdu = addr_book.prepare_provide_ledger_account_contact(
        hmac_proof_from,
        contact_name=DEFAULT_ACCOUNT_NAME,
        derivation_path=DEFAULT_BIP32_PATH,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0, \
        f"Provide Contact must return no data, got {response.data.hex()}"

    # Step 3: Register the recipient (To) account
    hmac_proof_to = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
        derivation_path=LEDGER_ACCOUNT_BIP32_PATH,
        contact_name=SECONDARY_ACCOUNT_NAME,
    )

    # Step 4: Derive the recipient address
    with app_client.get_public_addr(bip32_path=LEDGER_ACCOUNT_BIP32_PATH, display=False):
        pass
    _, recipient_addr, _ = ResponseParser.pk_addr(app_client.response().data)

    # Step 5: Provide Contact for the To account
    apdu = addr_book.prepare_provide_ledger_account_contact(
        hmac_proof_to,
        contact_name=SECONDARY_ACCOUNT_NAME,
        derivation_path=LEDGER_ACCOUNT_BIP32_PATH,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0, \
        f"Provide Contact must return no data, got {response.data.hex()}"

    # Step 6: Sign from the registered From account to the registered To account
    # Both "From" and "To" show their account names instead of raw addresses
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": recipient_addr,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


# =============================================================================
# Provide Contact Tests with EIP-712
# =============================================================================

def test_address_book_eip712_calldata_empty_send(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact name replaces raw address in EIP-712 calldata review.

    Flow:
      1. Register Identity (no screenshot comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign an EIP-712 Safe empty-calldata message to the same address
         → "To" field shows the contact name instead of the raw address
    """
    backend   = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    set_wallet_addr(backend)

    json_path = Path(eip712_json_path()) / "safe_empty.json"
    with json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    callee_addr = bytes.fromhex(data["message"]["to"][2:])

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=callee_addr,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(callee_addr, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign EIP-712 — "To" field shows contact name
    eip712_calldata_common(scenario_navigator, "safe_empty")


def test_address_book_eip712_typed_field(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact name replaces raw address in an EIP-712 typed field.

    Flow:
      1. Register Identity (no screenshot comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign an EIP-712 message whose address field is filtered as trusted_name
         → the address field shows the contact name instead of the raw address
    """
    backend   = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    set_wallet_addr(backend)

    contact_addr = bytes.fromhex("1111111111111111111111111111111111111111")

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=contact_addr,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(contact_addr, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign EIP-712 — "validator" field shows contact name
    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name",              "type": "string"},
                {"name": "version",           "type": "string"},
                {"name": "chainId",           "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Root": [
                {"name": "validator", "type": "address"},
                {"name": "enable",    "type": "bool"},
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name":              "test",
            "version":           "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "chainId":           1,
        },
        "message": {
            "validator": "0x" + contact_addr.hex(),
            "enable":    True,
        },
    }
    filters = {
        "name": "Trusted name test",
        "fields": {
            "validator": {
                "type":      "trusted_name",
                "name":      "Validator",
                "tn_type":   [TrustedNameType.ACCOUNT],
                "tn_source": [TrustedNameSource.CAL, TrustedNameSource.ENS],
            },
            "enable": {
                "type": "raw",
                "name": "State",
            },
        },
    }
    eip712_new_common(scenario_navigator, data, filters, scenario_navigator.test_name)


# =============================================================================
# Provide Contact Tests with GCS
# =============================================================================

def test_address_book_gcs_empty_tx(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact name replaces raw address in GCS empty-TX "To" field.

    Flow:
      1. Register Identity (no screenshot comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign a GCS batch with a single empty ETH send to the same address
         → "To" field shows the contact name instead of the raw address
    """
    backend   = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    callee_addr = bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=callee_addr,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(callee_addr, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign GCS batch — "To" shows contact name
    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=bytes.fromhex("2cc8475177918e8C4d840150b68815A4b6f0f5f3"),
        )

    data = contract.encode_abi("batchExecute", [[(callee_addr, Web3.to_wei(0.0, "ether"), b"")]])
    tx_params = {
        "nonce": 79,
        "maxFeePerGas": Web3.to_wei(4.8, "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei(2, "gwei"),
        "gas": 2000,
        "to": contract.address,
        "data": data,
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign("m/44'/60'/0'/0/0", tx_params, mode=SignMode.STORE):
        pass

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json", "batchExecute", "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(1, TypeFamily.BYTES,   data_path=DataPath(1, param_paths["data"])),
                Value(1, TypeFamily.ADDRESS, data_path=DataPath(1, param_paths["to"])),
            ),
        ),
    ]

    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1, DEFAULT_CHAIN_ID, contract.address,
        get_selector_from_data(data), inst_hash,
        "Batch transaction",
        creator_name="Ledger Multisig",
        creator_legal_name="Ledger",
    )
    app_client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        app_client.provide_transaction_field_desc(field.serialize())

    with app_client.sign(mode=SignMode.START_FLOW):
        scenario_navigator.review_approve()


def test_address_book_gcs_trusted_name_field(scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact: contact name replaces raw address in a GCS ParamTrustedName field.

    Flow:
      1. Register Identity (no screenshot comparison)
      2. Provide Contact (synchronous, no UI)
      3. Sign a GCS ERC-20 transfer where the recipient is typed as trusted_name
         → the recipient field shows the contact name instead of the raw address
    """
    backend   = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    recipient_addr = bytes.fromhex("1111111111111111111111111111111111111111")
    token_addr     = bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7")  # USDT

    # Step 1: Register Identity
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=recipient_addr,
        do_compare=False,
    )

    # Step 2: Provide Contact (synchronous, no UI)
    apdu = addr_book.prepare_provide_contact(recipient_addr, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 3: Sign GCS ERC-20 transfer — "To" field shows contact name
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=token_addr)

    data = contract.encode_abi("transfer", [recipient_addr, int(1.1 * pow(10, 6))])
    tx_params = {
        "nonce": 235,
        "maxFeePerGas": Web3.to_wei(100, "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei(10, "gwei"),
        "gas": 44001,
        "to": token_addr,
        "data": data,
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign("m/44'/60'/0'/0/0", tx_params, mode=SignMode.STORE):
        pass

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    fields = [
        Field(
            1,
            "To",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, data_path=DataPath(1, param_paths["_to"])),
                [TrustedNameType.ACCOUNT],
                [TrustedNameSource.ENS],
            )
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1, TypeFamily.UINT, 32, DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            )
        ),
    ]

    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1, DEFAULT_CHAIN_ID, token_addr,
        get_selector_from_data(data), inst_hash,
        "Transfer USDT",
        creator_name="Tether",
    )
    app_client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        app_client.provide_transaction_field_desc(field.serialize())

    with app_client.sign(mode=SignMode.START_FLOW):
        scenario_navigator.review_approve()


def test_address_book_gcs_combined_ab_and_tn(scenario_navigator: NavigateWithScenario) -> None:
    """Test GCS: combined Address Book + ENS display when both are available for the same address.

    When an Address Book contact and an ENS trusted name both resolve to the same address, the
    main tag/value shows the contact name (Alice) with scope as sub-name, exactly like
    the Address Book-only case. The detail view (tap on wallet, BOTH_CLICK on Nano) additionally
    shows the ENS name as an extra line/page after the raw address.

    Flow:
      1. Register Identity + Provide Contact (Address Book contact for recipient)
      2. Get challenge + Provide ENS trusted name for the same address
      3. Sign GCS ERC-20 transfer where the "To" field resolves to both
         → ADDRESS_BOOK_ALIAS with explanation = ENS name: scope + address + ENS in detail
    """
    backend = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book = AddressBookClient(backend)

    recipient_addr = bytes.fromhex("1111111111111111111111111111111111111111")
    token_addr = bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7")  # USDT

    # Step 1: Register Identity + Provide Contact
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        address=recipient_addr,
        do_compare=False,
    )
    apdu = addr_book.prepare_provide_contact(recipient_addr, group_handle, hmac_name, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)

    # Step 2: Provide ENS trusted name for the same address
    challenge = ResponseParser.challenge(app_client.get_challenge().data)
    app_client.provide_trusted_name(
        TrustedName(1, recipient_addr, "alice.eth", challenge=challenge, coin_type=CoinType.ETH)
    )

    # Step 3: Sign GCS ERC-20 transfer — "To" field shows combined Address Book+ENS view
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=token_addr)

    data = contract.encode_abi("transfer", [recipient_addr, int(1.1 * pow(10, 6))])
    tx_params = {
        "nonce": 235,
        "maxFeePerGas": Web3.to_wei(100, "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei(10, "gwei"),
        "gas": 44001,
        "to": token_addr,
        "data": data,
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign("m/44'/60'/0'/0/0", tx_params, mode=SignMode.STORE):
        pass

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    fields = [
        Field(
            1,
            "To",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, data_path=DataPath(1, param_paths["_to"])),
                [TrustedNameType.ACCOUNT],
                [TrustedNameSource.ENS],
            )
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1, TypeFamily.UINT, 32, DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            )
        ),
    ]

    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1, DEFAULT_CHAIN_ID, token_addr,
        get_selector_from_data(data), inst_hash,
        "Transfer USDT",
        creator_name="Tether",
    )
    app_client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        app_client.provide_transaction_field_desc(field.serialize())

    with app_client.sign(mode=SignMode.START_FLOW):
        scenario_navigator.review_approve()


# =============================================================================
# Provide Contact Tests — After Edit
# =============================================================================

def test_address_book_simple_tx_after_edit_identifier(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact after Edit Identifier: contact name persists after address change.

    Flow:
      1. Register Identity for DEFAULT_ADDRESS → (group_handle, hmac_name, hmac_rest_old)
      2. Edit Identifier (DEFAULT_ADDRESS → new_address) → hmac_rest_new
      3. Provide Contact (new_address, group_handle, hmac_name, hmac_rest_new)
      4. Sign TX to new_address → "To" shows DEFAULT_CONTACT_NAME
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_address = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Identifier (DEFAULT_ADDRESS → new_address)
    apdu = addr_book.prepare_edit_identifier(new_address, hmac_name, hmac_rest_old, group_handle)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_IDENTIFIER):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    hmac_rest_new = check_edit_identifier_response(app_client, new_address, group_handle)

    # Step 3: Provide Contact with the new address and new HMAC_REST
    apdu = addr_book.prepare_provide_contact(
        new_address,
        group_handle,
        hmac_name,
        hmac_rest_new,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 4: Sign TX to new_address — "To" shows DEFAULT_CONTACT_NAME
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": new_address,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_simple_tx_after_edit_scope(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact after Edit Scope: contact name persists after scope change.

    Flow:
      1. Register Identity → (group_handle, hmac_name, hmac_rest_old)
      2. Edit Scope (DEFAULT_SCOPE → new_scope) → hmac_rest_new
      3. Provide Contact (DEFAULT_ADDRESS, group_handle, hmac_name, hmac_rest_new, scope=new_scope)
      4. Sign TX to DEFAULT_ADDRESS → "To" shows DEFAULT_CONTACT_NAME
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_scope = "Eth Savings"

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name, hmac_rest_old = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Scope (DEFAULT_SCOPE → new_scope)
    apdu = addr_book.prepare_edit_scope(
        DEFAULT_SCOPE, new_scope, hmac_name, hmac_rest_old, group_handle,
    )
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_SCOPE):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    hmac_rest_new = check_edit_scope_response(app_client, new_scope, group_handle)

    # Step 3: Provide Contact with the new scope and new HMAC_REST
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS,
        group_handle,
        hmac_name,
        hmac_rest_new,
        scope=new_scope,
    )
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 4: Sign TX to DEFAULT_ADDRESS — "To" shows DEFAULT_CONTACT_NAME
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_simple_tx_ledger_account_rename(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Ledger Account Contact after rename: new name shown in TX review.

    Flow:
      1. Register Ledger Account at DEFAULT_BIP32_PATH → hmac_proof_old
      2. Edit Ledger Account (DEFAULT_ACCOUNT_NAME → new_name) → hmac_proof_new
      3. Provide Ledger Account Contact (new_name, hmac_proof_new)
      4. Sign TX from DEFAULT_BIP32_PATH → "From" shows new_name
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "ETH savings"

    # Step 1: Register Ledger Account (skip snapshot comparison)
    hmac_proof_old = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Edit Ledger Account (rename DEFAULT_ACCOUNT_NAME → new_name)
    apdu = addr_book.prepare_edit_ledger_account(new_name, hmac_proof_old)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_LEDGER_ACCOUNT):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    hmac_proof_new = check_edit_ledger_account_response(app_client, new_name)

    # Step 3: Provide Ledger Account Contact with the new name
    apdu = addr_book.prepare_provide_ledger_account_contact(
        hmac_proof_new,
        contact_name=new_name,
    )
    response = app_client.provide_address_book(
        addr_book, apdu,
        AddressBookSubCommand.SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT, False,
    )
    assert_sw(response.status, StatusWord.SWO_SUCCESS)
    assert len(response.data) == 0

    # Step 4: Sign TX — "From" shows new_name instead of raw address
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


# =============================================================================
# Provide Contact Tests — Cache Invalidation after Edit
#
# These tests verify that on_edit_X_applied() evicts the stale cache entry so
# that a subsequent sign shows the raw address (not the now-wrong contact name).
# The contact is provided BEFORE the edit, which is the key difference from the
# "Provide Contact after Edit" tests above.
# =============================================================================

def test_address_book_cache_invalidation_after_edit_contact_name(
        scenario_navigator: NavigateWithScenario) -> None:
    """Edit Contact Name updates the cached entry in place.

    Without on_edit_contact_name_applied(), the cached entry for DEFAULT_ADDRESS
    keeps the old name: the TX still shows "Alice" after the rename. After the
    fix the cache is updated in place and no re-provide is needed.

    Flow:
      1. Register Identity  → (group_handle, hmac_name_old, hmac_rest)
      2. Provide Contact (DEFAULT_CONTACT_NAME) → cached as "Alice"
      3. Edit Contact Name ("Alice" → new_name) → cache updated in place
      4. Sign TX to DEFAULT_ADDRESS (no re-provide) → "To" shows new_name
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "Alice Renamed"

    # Step 1: Register Identity
    group_handle, hmac_name_old, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Contact → cache entry for DEFAULT_ADDRESS / "Alice"
    apdu = addr_book.prepare_provide_contact(DEFAULT_ADDRESS, group_handle, hmac_name_old, hmac_rest)
    response = app_client.provide_address_book(addr_book, apdu,
                                               AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False)
    assert_sw(response.status, StatusWord.SWO_SUCCESS)

    # Step 3: Edit Contact Name → on_edit_contact_name_applied() updates "Alice" → new_name
    apdu = addr_book.prepare_edit_contact_name(DEFAULT_CONTACT_NAME, new_name,
                                               hmac_name_old, group_handle)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    check_edit_contact_name_response(app_client, new_name, group_handle)

    # Step 4: Sign TX without re-providing — "To" must show new_name, not "Alice"
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


def test_address_book_cache_invalidation_after_ledger_account_rename(
        scenario_navigator: NavigateWithScenario) -> None:
    """Ledger Account rename updates the cached entry in place.

    Without on_edit_ledger_account_applied(), the cached entry keeps the old name
    and the TX still shows DEFAULT_ACCOUNT_NAME after the rename. After the fix
    the cache is updated in place and no re-provide is needed.

    Flow:
      1. Register Ledger Account  → hmac_proof_old
      2. Provide Ledger Account Contact (DEFAULT_ACCOUNT_NAME) → cached
      3. Edit Ledger Account (DEFAULT_ACCOUNT_NAME → new_name) → cache updated in place
      4. Sign TX (no re-provide) → "From" shows new_name
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    new_name = "ETH savings renamed"

    # Step 1: Register Ledger Account
    hmac_proof_old = _common_register_ledger_account(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Ledger Account Contact → cache entry for DEFAULT_ACCOUNT_NAME
    apdu = addr_book.prepare_provide_ledger_account_contact(hmac_proof_old)
    response = app_client.provide_address_book(
        addr_book, apdu,
        AddressBookSubCommand.SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT, False,
    )
    assert_sw(response.status, StatusWord.SWO_SUCCESS)

    # Step 3: Rename → on_edit_ledger_account_applied() updates name in place
    apdu = addr_book.prepare_edit_ledger_account(new_name, hmac_proof_old)
    with app_client.provide_address_book(addr_book, apdu,
                                         AddressBookSubCommand.SUB_CMD_EDIT_LEDGER_ACCOUNT):
        scenario_navigator.address_review_approve(do_comparison=False, custom_screen_text="Confirm")
    check_edit_ledger_account_response(app_client, new_name)

    # Step 4: Sign TX without re-providing — "From" must show new_name
    tx_params: dict = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": DEFAULT_ADDRESS,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": DEFAULT_CHAIN_ID,
    }
    with app_client.sign(DEFAULT_BIP32_PATH, tx_params):
        scenario_navigator.review_approve()


# =============================================================================
# Provide Contact Tests — Invalid HMAC
# =============================================================================

def test_address_book_provide_contact_invalid_hmac(
        scenario_navigator: NavigateWithScenario) -> None:
    """Test Provide Contact with corrupted HMACs: device rejects with 0x6982.

    The device verifies both HMAC_NAME and HMAC_REST inside Provide Contact.
    A single flipped bit in either proof must cause the command to fail with
    SWO_SECURITY_CONDITION_NOT_SATISFIED (0x6982).

    Flow:
      1. Register Identity → (group_handle, hmac_name, hmac_rest)
      2. Provide Contact with corrupted HMAC_NAME → 0x6982
      3. Provide Contact with valid HMAC_NAME but corrupted HMAC_REST → 0x6982
    """
    backend    = scenario_navigator.backend
    app_client = EthAppClient(backend)
    addr_book  = AddressBookClient(backend)

    # Step 1: Register Identity (skip snapshot comparison)
    group_handle, hmac_name, hmac_rest = _common_register_identity(
        scenario_navigator, app_client, addr_book,
        do_compare=False,
    )

    # Step 2: Provide Contact with corrupted HMAC_NAME — device must reject
    corrupted_hmac_name = bytes(b ^ 0xff for b in hmac_name)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS, group_handle, corrupted_hmac_name, hmac_rest,
    )
    try:
        response = app_client.provide_address_book(
            addr_book, apdu,
            AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False,
        )
        assert_sw(response.status, StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED)
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED)

    # Step 3: Provide Contact with valid HMAC_NAME but corrupted HMAC_REST
    corrupted_hmac_rest = bytes(b ^ 0xff for b in hmac_rest)
    apdu = addr_book.prepare_provide_contact(
        DEFAULT_ADDRESS, group_handle, hmac_name, corrupted_hmac_rest,
    )
    try:
        response = app_client.provide_address_book(
            addr_book, apdu,
            AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT, False,
        )
        assert_sw(response.status, StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED)
    except ExceptionRAPDU as e:
        assert_sw(e.status, StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED)
