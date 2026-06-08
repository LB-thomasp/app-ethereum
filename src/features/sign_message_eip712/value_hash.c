#include "value_hash.h"
#include "typed_data.h"
#include "context_712.h"
#include "type_hash.h"
#include "encode_field.h"
#include "hash_bytes.h"
#include "app_mem_utils.h"
#include "common_utils.h"    // CX_KECCAK_256_SIZE
#include "shared_context.h"  // tmpCtx

static bool hash_value(const s_struct_712_value *node, uint8_t *out, uint8_t depth);

/**
 * Encode a VAL_ATOMIC leaf to 32 bytes.
 * Static types: encode+pad. Dynamic types (string/bytes): keccak256(data).
 */
static bool encode_atomic(const s_struct_712_value *leaf, uint8_t *out) {
    const s_struct_712_field *field = leaf->field;
    const uint8_t *data = leaf->data;
    uint16_t length = leaf->length;
    void *encoded;

    if (IS_DYN(field->type)) {
        cx_sha3_t sha3;
        if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
            PRINTF("encode_atomic: keccak_init failed for dyn field %s\n", field->key_name);
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        hash_nbytes(data, length, (cx_hash_t *) &sha3);
        return finalize_hash((cx_hash_t *) &sha3, out, CX_KECCAK_256_SIZE);
    }

    switch (field->type) {
        case TYPE_SOL_UINT:
            encoded = encode_uint(data, (uint8_t) length);
            break;
        case TYPE_SOL_INT:
            encoded = encode_int(data, (uint8_t) length, field->type_size);
            break;
        case TYPE_SOL_BYTES_FIX:
            encoded = encode_bytes(data, (uint8_t) length);
            break;
        case TYPE_SOL_ADDRESS:
            encoded = encode_address(data, (uint8_t) length);
            break;
        case TYPE_SOL_BOOL:
            encoded = encode_boolean((const bool *) data, (uint8_t) length);
            break;
        default:
            PRINTF("encode_atomic: unknown type %d for field %s\n", field->type, field->key_name);
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
    }
    if (encoded == NULL) {
        PRINTF("encode_atomic: encode failed type=%d len=%d for field %s\n",
               field->type,
               (int) length,
               field->key_name);
        return false;
    }

    memcpy(out, encoded, EIP_712_ENCODED_FIELD_LENGTH);
    APP_MEM_FREE(encoded);
    return true;
}

/**
 * Hash an array: keccak256(enc(elem[0]) || enc(elem[1]) || ...).
 */
static bool hash_array(const s_struct_712_value *arr, uint8_t *out, uint8_t depth) {
    cx_sha3_t sha3;
    uint8_t elem_hash[CX_KECCAK_256_SIZE];

    if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    for (const s_struct_712_value *elem = arr->children; elem != NULL;
         elem = (const s_struct_712_value *) ((const flist_node_t *) elem)->next) {
        if (!hash_value(elem, elem_hash, depth)) return false;
        hash_nbytes(elem_hash, CX_KECCAK_256_SIZE, (cx_hash_t *) &sha3);
    }
    return finalize_hash((cx_hash_t *) &sha3, out, CX_KECCAK_256_SIZE);
}

/**
 * Hash a struct: keccak256(typeHash || enc(field[0]) || enc(field[1]) || ...).
 * Each recursive call holds its own cx_sha3_t on the stack (bounded by schema depth).
 */
static bool hash_struct(const s_struct_712_value *node, uint8_t *out, uint8_t depth) {
    cx_sha3_t sha3;
    uint8_t type_hash_buf[CX_KECCAK_256_SIZE];
    uint8_t child_hash[CX_KECCAK_256_SIZE];
    const char *name = node->struct_type->name;

    if (depth > IMPL_MAX_DEPTH) {
        PRINTF("hash_struct: max depth exceeded\n");
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    PRINTF("hash_struct: %s\n", name);

    if (!type_hash(name, (uint8_t) strlen(name), type_hash_buf)) {
        PRINTF("hash_struct: type_hash failed for %s\n", name);
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    hash_nbytes(type_hash_buf, CX_KECCAK_256_SIZE, (cx_hash_t *) &sha3);

    for (const s_struct_712_value *child = node->children; child != NULL;
         child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
        if (!hash_value(child, child_hash, depth + 1)) return false;
        hash_nbytes(child_hash, CX_KECCAK_256_SIZE, (cx_hash_t *) &sha3);
    }
    return finalize_hash((cx_hash_t *) &sha3, out, CX_KECCAK_256_SIZE);
}

static bool hash_value(const s_struct_712_value *node, uint8_t *out, uint8_t depth) {
    switch (node->kind) {
        case VAL_ATOMIC:
            return encode_atomic(node, out);
        case VAL_STRUCT:
            return hash_struct(node, out, depth);
        case VAL_ARRAY:
            return hash_array(node, out, depth);
        default:
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
    }
}

/**
 * Run hash pass over the complete EIP-712 value tree.
 *
 * Computes hashStruct(domain) and hashStruct(message) and writes results to
 * tmpCtx.messageSigningContext712.domainHash / .messageHash.
 *
 * Must be called only after impl_is_complete() returns true.
 * Domain special fields (chainId, verifyingContract) are extracted when the domain is complete
 * and accessible via impl_get_domain_chain_id() / impl_get_domain_contract_addr().
 */
bool value_hash_pass(const s_eip712_impl *impl) {
    uint8_t hash[CX_KECCAK_256_SIZE];

    if (impl == NULL) {
        return false;
    }

    if ((impl->domain == NULL) || !hash_struct(impl->domain, hash, 0)) {
        PRINTF("value_hash_pass: domain hash failed\n");
        return false;
    }
    memcpy(tmpCtx.messageSigningContext712.domainHash, hash, CX_KECCAK_256_SIZE);

    if ((impl->message == NULL) || !hash_struct(impl->message, hash, 0)) {
        PRINTF("value_hash_pass: message hash failed\n");
        return false;
    }
    memcpy(tmpCtx.messageSigningContext712.messageHash, hash, CX_KECCAK_256_SIZE);

    return true;
}
