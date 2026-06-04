#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "lists.h"
#include "common_utils.h"

typedef enum { ARRAY_DYNAMIC = 0, ARRAY_FIXED_SIZE, ARRAY_TYPES_COUNT } e_array_type;

typedef enum {
    // contract defined struct
    TYPE_STRUCT = 0,
    // native types
    TYPE_SOL_INT,
    TYPE_SOL_UINT,
    TYPE_SOL_ADDRESS,
    TYPE_SOL_BOOL,
    TYPE_SOL_STRING,
    TYPE_SOL_BYTES_FIX,
    TYPE_SOL_BYTES_DYN,
    TYPES_COUNT
} e_type;

typedef struct {
    e_array_type type;
    uint8_t size;
} s_struct_712_field_array_level;

typedef struct {
    flist_node_t _list;
    union {
        char *struct_name;
        uint8_t type_size;
    };
    char *key_name;
    s_struct_712_field_array_level *array_levels;
    uint8_t array_level_count;
    e_type type;
} s_struct_712_field;

typedef struct {
    flist_node_t _list;
    char *name;
    s_struct_712_field *fields;
} s_struct_712;

typedef enum { VAL_ATOMIC, VAL_STRUCT, VAL_ARRAY } e_val_kind;

#define IS_DYN(type) (((type) == TYPE_SOL_STRING) || ((type) == TYPE_SOL_BYTES_DYN))

typedef enum { ROOT_NONE = 0, ROOT_DOMAIN, ROOT_MESSAGE } e_root_type;

typedef struct struct_712_value {
    flist_node_t _list;
    union {
        const s_struct_712_field *field;  // VAL_ATOMIC, VAL_ARRAY
        const s_struct_712 *struct_type;  // VAL_STRUCT
    };
    union {
        struct {
            uint8_t *data;
            uint16_t length;
        };  // VAL_ATOMIC
        struct struct_712_value *children;  // VAL_STRUCT, VAL_ARRAY
    };
    e_val_kind kind;
} s_struct_712_value;

typedef struct {
    s_struct_712_value *domain;   // VAL_STRUCT → EIP712Domain
    s_struct_712_value *message;  // VAL_STRUCT → primaryType
} s_eip712_impl;

#define IMPL_MAX_DEPTH 16

const char *get_struct_field_typename(const s_struct_712_field *ptr);
e_array_type struct_field_array_depth(const uint8_t *ptr, uint8_t *array_size);
const s_struct_712 *get_struct_list(void);
const s_struct_712 *get_structn(const char *name_ptr, uint8_t name_length);
bool set_struct_name(uint8_t length, const uint8_t *name);
bool set_struct_field(uint8_t length, const uint8_t *data);
bool typed_data_init(void);
void typed_data_deinit(void);

bool impl_set_root(const char *name, size_t length);
bool impl_new_array(size_t count);
// Returns the completed leaf on final chunk, in-progress leaf on intermediate chunks, NULL on
// error.
const s_struct_712_value *impl_add_field(const uint8_t *data, size_t length, bool more);
bool impl_is_complete(void);
bool impl_hash_pass(void);

e_root_type impl_get_root_type(void);
const s_struct_712_field *impl_get_current_field(void);
uint8_t impl_get_depth_count(void);
const s_struct_712_field *impl_get_nth_field(uint8_t n);
const s_struct_712 *impl_get_nth_struct_to_last(uint8_t n);
uint8_t impl_backup_get_depth_count(void);
const s_struct_712_field *impl_backup_get_nth_field(uint8_t n);
bool impl_backup_exists(const char *path, size_t length);

bool impl_get_domain_chain_id(uint64_t *chain_id);
bool impl_get_domain_contract_addr(uint8_t addr[ADDRESS_LENGTH]);

// Visitor callback for value tree traversal. Return false to abort traversal.
typedef bool (*f_value_visitor)(const s_struct_712_value *node, void *context);

bool impl_traverse_domain(f_value_visitor visitor, void *context);
bool impl_traverse_message(f_value_visitor visitor, void *context);
