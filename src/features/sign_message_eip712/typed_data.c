#include "typed_data.h"
#include "sol_typenames.h"
#include "apdu_constants.h"  // APDU response codes
#include "context_712.h"
#include "common_utils.h"
#include "app_mem_utils.h"
#include "read.h"
#include "value_hash.h"

static s_struct_712 *g_structs = NULL;

/**
 * Initialize the typed data context
 *
 * @return whether the memory allocation was successful
 */
bool typed_data_init(void) {
    if (g_structs != NULL) {
        typed_data_deinit();
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_field(s_struct_712_field *f) {
    if (f->type == TYPE_STRUCT) {
        APP_MEM_FREE(f->struct_name);
    }
    APP_MEM_FREE(f->array_levels);
    APP_MEM_FREE(f->key_name);
    APP_MEM_FREE(f);
}

// to be used as a \ref f_list_node_del
static void delete_struct(s_struct_712 *s) {
    APP_MEM_FREE(s->name);
    flist_clear((flist_node_t **) &s->fields, (f_list_node_del) &delete_field);
    APP_MEM_FREE(s);
}

// forward declaration
static void impl_deinit(void);

void typed_data_deinit(void) {
    impl_deinit();
    flist_clear((flist_node_t **) &g_structs, (f_list_node_del) &delete_struct);
}

/**
 * Get type name from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @return type name pointer
 */
const char *get_struct_field_typename(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL) {
        return NULL;
    }
    if (field_ptr->type == TYPE_STRUCT) {
        return field_ptr->struct_name;
    }
    return get_struct_field_sol_typename(field_ptr);
}

const s_struct_712 *get_struct_list(void) {
    return g_structs;
}

/**
 * Find struct with a given name
 *
 * @param[in] name struct name
 * @param[in] length name length
 * @return pointer to struct
 */
const s_struct_712 *get_structn(const char *name, uint8_t length) {
    const s_struct_712 *struct_ptr;

    if (name == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return NULL;
    }
    for (struct_ptr = get_struct_list(); struct_ptr != NULL;
         struct_ptr = (s_struct_712 *) ((flist_node_t *) struct_ptr)->next) {
        if (struct_ptr->name != NULL) {
            if ((length == strlen(struct_ptr->name)) &&
                (memcmp(name, struct_ptr->name, length) == 0)) {
                return struct_ptr;
            }
        }
    }
    apdu_response_code = SWO_INCORRECT_DATA;
    return NULL;
}

/**
 * Set struct name
 *
 * @param[in] length name length
 * @param[in] name name
 * @return whether it was successful
 */
bool set_struct_name(uint8_t length, const uint8_t *name) {
    s_struct_712 *new_struct;

    if (name == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (APP_MEM_CALLOC((void **) &new_struct, sizeof(*new_struct)) == false) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    if ((new_struct->name = APP_MEM_ALLOC(length + 1)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    new_struct->name[length] = '\0';
    memmove(new_struct->name, name, length);

    flist_push_back((flist_node_t **) &g_structs, (flist_node_t *) new_struct);
    return true;
}

// TypeDesc masks
#define TYPE_MASK     (0xF)
#define ARRAY_MASK    (1 << 7)
#define TYPESIZE_MASK (1 << 6)
#define TYPENAME_ENUM (0xF)

/**
 * Set struct field TypeDesc
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful or not
 */
static bool set_struct_field_typedesc(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length,
                                      bool *is_array,
                                      bool *has_size) {
    uint8_t typedesc;

    // copy TypeDesc
    if ((*data_idx + sizeof(typedesc)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    typedesc = data[(*data_idx)++];
    *is_array = typedesc & ARRAY_MASK;
    *has_size = typedesc & TYPESIZE_MASK;
    field->type = typedesc & TYPE_MASK;
    return true;
}

/**
 * Set struct field custom typename
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_custom_typename(s_struct_712_field *field,
                                             const uint8_t *data,
                                             uint8_t *data_idx,
                                             uint8_t length) {
    uint8_t typename_len;

    // copy custom struct name length
    if ((*data_idx + sizeof(typename_len)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    typename_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + typename_len) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if ((field->struct_name = APP_MEM_ALLOC(typename_len + 1)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    field->struct_name[typename_len] = '\0';
    memmove(field->struct_name, &data[*data_idx], typename_len);
    *data_idx += typename_len;
    return true;
}

/**
 * Set struct field's array levels
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_array(s_struct_712_field *field,
                                   const uint8_t *data,
                                   uint8_t *data_idx,
                                   uint8_t length) {
    if ((*data_idx + sizeof(field->array_level_count)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    field->array_level_count = data[(*data_idx)++];
    if ((field->array_levels =
             APP_MEM_ALLOC(sizeof(*field->array_levels) * field->array_level_count)) == NULL) {
        return false;
    }
    for (int idx = 0; idx < field->array_level_count; ++idx) {
        if ((*data_idx + sizeof(field->array_levels[idx].type)) > length)  // check buffer bound
        {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        field->array_levels[idx].type = data[(*data_idx)++];
        switch (field->array_levels[idx].type) {
            case ARRAY_DYNAMIC:  // nothing to do
                break;
            case ARRAY_FIXED_SIZE:
                if ((*data_idx + sizeof(field->array_levels[idx].size)) >
                    length)  // check buffer bound
                {
                    apdu_response_code = SWO_INCORRECT_DATA;
                    return false;
                }
                field->array_levels[idx].size = data[(*data_idx)++];
                break;
            default:
                // should not be in here :^)
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
        }
    }
    return true;
}

/**
 * Set struct field's type size
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_typesize(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    // copy TypeSize
    if ((*data_idx + sizeof(field->type_size)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    field->type_size = data[(*data_idx)++];
    return true;
}

/**
 * Set struct field's key name
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_keyname(s_struct_712_field *field,
                                     const uint8_t *data,
                                     uint8_t *data_idx,
                                     uint8_t length) {
    uint8_t keyname_len;

    // copy length
    if ((*data_idx + sizeof(keyname_len)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    keyname_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + keyname_len) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((field->key_name = APP_MEM_ALLOC(keyname_len + 1)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    field->key_name[keyname_len] = '\0';
    memmove(field->key_name, &data[*data_idx], keyname_len);
    *data_idx += keyname_len;
    return true;
}

static bool set_struct_field_internal(s_struct_712_field **new_field_ptr,
                                      uint8_t length,
                                      const uint8_t *data) {
    s_struct_712_field *new_field;
    uint8_t data_idx = 0;

    if ((data == NULL) || (length == 0)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    } else if (g_structs == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((new_field = APP_MEM_ALLOC(sizeof(*new_field))) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    *new_field_ptr = new_field;
    explicit_bzero(new_field, sizeof(*new_field));

    bool is_array;
    bool has_size;
    if (!set_struct_field_typedesc(new_field, data, &data_idx, length, &is_array, &has_size)) {
        return false;
    }

    // check TypeSize flag in TypeDesc
    if (has_size) {
        // TYPESIZE and TYPE_STRUCT are mutually exclusive
        if (new_field->type == TYPE_STRUCT) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }

        if (set_struct_field_typesize(new_field, data, &data_idx, length) == false) {
            return false;
        }

    } else if (new_field->type == TYPE_STRUCT) {
        if (set_struct_field_custom_typename(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }
    if (is_array) {
        if (set_struct_field_array(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }

    if (set_struct_field_keyname(new_field, data, &data_idx, length) == false) {
        return false;
    }

    if (data_idx != length)  // check that there is no more
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    // get last struct
    s_struct_712 *s = g_structs;
    while ((s_struct_712 *) ((flist_node_t *) s)->next != NULL) {
        s = (s_struct_712 *) ((flist_node_t *) s)->next;
    }

    flist_push_back((flist_node_t **) &s->fields, (flist_node_t *) new_field);
    return true;
}

/**
 * Set struct field
 *
 * @param[in] length data length
 * @param[in] data the field data
 * @return whether it was successful
 */
bool set_struct_field(uint8_t length, const uint8_t *data) {
    s_struct_712_field *new_field = NULL;

    if (!set_struct_field_internal(&new_field, length, data)) {
        if (new_field != NULL) {
            delete_field(new_field);
        }
        return false;
    }
    return true;
}

typedef struct {
    const s_struct_712_field *next;  // next field expecting data
    s_struct_712_value *node;        // VAL_STRUCT or VAL_ARRAY being built
    uint8_t array_remaining;         // >0 = array frame; 0 = struct frame
} s_build_frame;

static struct {
    s_build_frame stack[IMPL_MAX_DEPTH];
    uint8_t depth;
} g_build;
static struct {
    s_build_frame stack[IMPL_MAX_DEPTH];
    uint8_t depth;
} g_backup;
static s_eip712_impl g_impl;
static struct {
    s_struct_712_value *leaf;
    uint16_t filled;
} g_pending_field;

// --- helpers ---

static s_struct_712_value *alloc_value(e_val_kind kind) {
    s_struct_712_value *v = NULL;

    if ((v = APP_MEM_ALLOC(sizeof(*v))) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return NULL;
    }
    explicit_bzero(v, sizeof(*v));
    v->kind = kind;
    return v;
}

static void append_child(s_struct_712_value *parent, s_struct_712_value *child) {
    flist_push_back((flist_node_t **) &parent->children, (flist_node_t *) child);
}

static bool push_frame(const s_struct_712_field *next,
                       s_struct_712_value *node,
                       uint8_t array_remaining) {
    if (g_build.depth >= IMPL_MAX_DEPTH) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    g_build.stack[g_build.depth].next = next;
    g_build.stack[g_build.depth].node = node;
    g_build.stack[g_build.depth].array_remaining = array_remaining;
    g_build.depth++;
    return true;
}

// Auto-descend into TYPE_STRUCT fields that have no array levels.
// Called whenever a new struct frame is pushed, to skip past nested struct fields
// that don't need an explicit P2_IMPL_ARRAY or P2_IMPL_FIELD to introduce them.
static bool auto_descend(void) {
    while (g_build.depth > 0) {
        s_build_frame *f = &g_build.stack[g_build.depth - 1];
        if (f->next == NULL) break;
        if (f->next->type != TYPE_STRUCT) break;
        if (f->next->array_level_count > 0) break;  // array → wait for P2_IMPL_ARRAY

        const s_struct_712 *nested =
            get_structn(f->next->struct_name, strlen(f->next->struct_name));
        if (!nested) return false;

        s_struct_712_value *node = alloc_value(VAL_STRUCT);
        if (!node) return false;
        node->struct_type = nested;
        append_child(f->node, node);

        if (!push_frame(nested->fields, node, 0)) return false;
    }
    return true;
}

// Advance cursor after a leaf is fully received or an array element is done.
static bool advance(void) {
    while (g_build.depth > 0) {
        s_build_frame *f = &g_build.stack[g_build.depth - 1];

        if (f->array_remaining > 0) {
            f->array_remaining--;
            if (f->array_remaining == 0) {
                // array frame exhausted — pop and let the loop handle the parent naturally:
                // if parent is a struct frame it will advance next; if it is another array
                // frame it will decrement its own remaining.
                g_build.depth--;
                continue;
            }
            // more array elements — push next element if TYPE_STRUCT
            if (f->next->type == TYPE_STRUCT) {
                const s_struct_712 *nested =
                    get_structn(f->next->struct_name, strlen(f->next->struct_name));
                if (!nested) return false;
                s_struct_712_value *elem = alloc_value(VAL_STRUCT);
                if (!elem) return false;
                elem->struct_type = nested;
                append_child(f->node, elem);
                if (!push_frame(nested->fields, elem, 0)) return false;
                return auto_descend();
            }
            return true;  // next leaf arrives via next impl_add_field call
        } else {
            f->next = (const s_struct_712_field *) ((flist_node_t *) f->next)->next;
        }

        if (g_build.depth == 0) return true;
        f = &g_build.stack[g_build.depth - 1];

        if (f->next == NULL) {
            // struct complete — pop and keep advancing
            g_build.depth--;
            continue;
        }

        return auto_descend();
    }
    return true;
}

// --- value tree deinit ---

static void delete_value(s_struct_712_value *v) {
    if (v->kind == VAL_ATOMIC) {
        APP_MEM_FREE(v->data);
    } else {
        flist_clear((flist_node_t **) &v->children, (f_list_node_del) &delete_value);
    }
    APP_MEM_FREE(v);
}

static void impl_deinit(void) {
    if (g_impl.domain != NULL) {
        delete_value(g_impl.domain);
        g_impl.domain = NULL;
    }
    if (g_impl.message != NULL) {
        delete_value(g_impl.message);
        g_impl.message = NULL;
    }
    g_build.depth = 0;
    g_backup.depth = 0;
    g_pending_field.leaf = NULL;
    g_pending_field.filled = 0;
}

bool impl_set_root(const char *name, size_t length) {
    const s_struct_712 *root = get_structn(name, (uint8_t) length);
    if (!root) return false;

    s_struct_712_value *node = alloc_value(VAL_STRUCT);
    if (!node) return false;
    node->struct_type = root;

    if (g_impl.domain == NULL) {
        g_impl.domain = node;
    } else {
        g_impl.message = node;
    }

    g_build.depth = 0;
    if (!push_frame(root->fields, node, 0)) return false;
    return auto_descend();
}

bool impl_new_array(size_t count) {
    if (g_build.depth == 0) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    s_build_frame *f = &g_build.stack[g_build.depth - 1];

    s_struct_712_value *arr = alloc_value(VAL_ARRAY);
    if (!arr) return false;
    arr->field = f->next;
    append_child(f->node, arr);

    if (count == 0) {
        // empty array — snapshot only struct-level frames for filtering discarded-path checks.
        // Array-container frames (array_remaining > 0) are skipped: they store the same field
        // descriptor as their parent struct frame, causing duplicate prefix segments when
        // matches_backup_path iterates over the backup depth.
        g_backup.depth = 0;
        for (uint8_t i = 0; i < g_build.depth; ++i) {
            if (g_build.stack[i].array_remaining == 0) {
                g_backup.stack[g_backup.depth++] = g_build.stack[i];
            }
        }
        // advance past this field
        return advance();
    }

    if (count > UINT8_MAX) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (!push_frame(f->next, arr, (uint8_t) count)) return false;

    // if elements are TYPE_STRUCT, push first element immediately
    if (f->next->type == TYPE_STRUCT) {
        const s_struct_712 *nested =
            get_structn(f->next->struct_name, strlen(f->next->struct_name));
        if (!nested) return false;
        s_struct_712_value *elem = alloc_value(VAL_STRUCT);
        if (!elem) return false;
        elem->struct_type = nested;
        append_child(arr, elem);
        if (!push_frame(nested->fields, elem, 0)) return false;
        return auto_descend();
    }
    return true;
}

bool impl_is_complete(void) {
    return (g_build.depth == 0) && (g_impl.message != NULL);
}

const s_struct_712_value *impl_add_field(const uint8_t *data, size_t length, bool more) {
    if (g_build.depth == 0) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return NULL;
    }

    if (g_pending_field.leaf == NULL) {
        // first chunk: data starts with uint16_t total_size
        if (length < sizeof(uint16_t)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return NULL;
        }
        uint16_t total_size = read_u16_be(data, 0);
        data += sizeof(uint16_t);
        length -= sizeof(uint16_t);

        s_struct_712_value *leaf = alloc_value(VAL_ATOMIC);
        if (!leaf) return NULL;

        s_build_frame *f = &g_build.stack[g_build.depth - 1];
        leaf->field = f->next;
        leaf->length = total_size;

        if (total_size > 0) {
            if ((leaf->data = APP_MEM_ALLOC(total_size)) == NULL) {
                apdu_response_code = SWO_INSUFFICIENT_MEMORY;
                APP_MEM_FREE(leaf);
                return NULL;
            }
        }
        append_child(f->node, leaf);

        g_pending_field.leaf = leaf;
        g_pending_field.filled = 0;
    }

    if (g_pending_field.filled + length > g_pending_field.leaf->length) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return NULL;
    }
    if (length > 0) {
        memmove(g_pending_field.leaf->data + g_pending_field.filled, data, length);
        g_pending_field.filled += (uint16_t) length;
    }

    if (!more) {
        if (g_pending_field.filled != g_pending_field.leaf->length) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return NULL;
        }
        s_struct_712_value *completed = g_pending_field.leaf;
        g_pending_field.leaf = NULL;
        g_pending_field.filled = 0;
        if (!advance()) return NULL;
        return completed;
    }
    return g_pending_field.leaf;
}

// --- path-compatible accessors (derived from build stack) ---

e_root_type impl_get_root_type(void) {
    if (g_impl.domain == NULL) return ROOT_NONE;
    if (g_impl.message == NULL) return ROOT_DOMAIN;
    return ROOT_MESSAGE;
}

const s_struct_712_field *impl_get_current_field(void) {
    if (g_build.depth == 0) return NULL;
    return g_build.stack[g_build.depth - 1].next;
}

uint8_t impl_get_depth_count(void) {
    uint8_t count = 0;
    for (uint8_t i = 0; i < g_build.depth; ++i) {
        if (g_build.stack[i].array_remaining == 0) count++;
    }
    return count;
}

const s_struct_712_field *impl_get_nth_field(uint8_t n) {
    if (n == 0) return NULL;
    uint8_t count = 0;
    for (uint8_t i = 0; i < g_build.depth; ++i) {
        if (g_build.stack[i].array_remaining == 0) {
            count++;
            if (count == n) return g_build.stack[i].next;
        }
    }
    return NULL;
}

const s_struct_712 *impl_get_nth_struct_to_last(uint8_t n) {
    if (n > g_build.depth) return NULL;
    uint8_t idx = g_build.depth - n;
    s_struct_712_value *node = g_build.stack[idx].node;
    if (node == NULL || node->kind != VAL_STRUCT) return NULL;
    return node->struct_type;
}

uint8_t impl_backup_get_depth_count(void) {
    return g_backup.depth;
}

const s_struct_712_field *impl_backup_get_nth_field(uint8_t n) {
    if (n == 0 || n > g_backup.depth) return NULL;
    return g_backup.stack[n - 1].next;
}

bool impl_backup_exists(const char *path, size_t length) {
    size_t offset = 0;
    size_t i;
    const s_struct_712_field *field_ptr;
    const char *typename;
    const s_struct_712 *struct_ptr;
    const char *key;

    if (g_backup.depth == 0) return false;
    field_ptr = g_backup.stack[g_backup.depth - 1].next;
    if (field_ptr == NULL) return false;

    while (offset < length) {
        if (((offset + 1) > length) || (memcmp(path + offset, ".", 1) != 0)) {
            return false;
        }
        offset += 1;
        if (((offset + 2) <= length) && (memcmp(path + offset, "[]", 2) == 0)) {
            if (field_ptr->array_level_count == 0) {
                return false;
            }
            offset += 2;
        } else if (offset < length) {
            for (i = 0; ((offset + i) < length) && (path[offset + i] != '.'); ++i);
            typename = field_ptr->struct_name;
            if ((struct_ptr = get_structn(typename, strlen(typename))) == NULL) {
                return false;
            }
            for (field_ptr = struct_ptr->fields; field_ptr != NULL;
                 field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
                key = field_ptr->key_name;
                if ((strlen(key) == i) && (memcmp(key, path + offset, i) == 0)) {
                    break;
                }
            }
            if (field_ptr == NULL) {
                return false;
            }
            offset += i;
        } else {
            return false;
        }
    }
    return true;
}

/**
 * Fill @p chain_id with the chainId from the domain value tree.
 *
 * @return true if the field was found and copied into @p chain_id, false otherwise.
 */
bool impl_get_domain_chain_id(uint64_t *chain_id) {
    if (g_impl.domain != NULL) {
        for (const s_struct_712_value *child = g_impl.domain->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if ((child->kind == VAL_ATOMIC) && (strcmp(child->field->key_name, "chainId") == 0)) {
                *chain_id = u64_from_BE(child->data, (uint8_t) child->length);
                return true;
            }
        }
    }
    return false;
}

/**
 * Fill @p addr with the verifyingContract from the domain value tree.
 *
 * @return true if the field was found and copied into @p addr, false otherwise.
 */
bool impl_get_domain_contract_addr(uint8_t addr[ADDRESS_LENGTH]) {
    const char *ethermint_vc = "cosmos";

    explicit_bzero(addr, ADDRESS_LENGTH);

    if (g_impl.domain != NULL) {
        for (const s_struct_712_value *child = g_impl.domain->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if (child->kind != VAL_ATOMIC) continue;
            if (strcmp(child->field->key_name, "verifyingContract") != 0) continue;

            const uint8_t *data = child->data;
            uint16_t length = child->length;

            switch (child->field->type) {
                case TYPE_SOL_ADDRESS:
                    if (length > ADDRESS_LENGTH) {
                        PRINTF("Error: verifyingContract too big\n");
                        return false;
                    }
                    break;
                case TYPE_SOL_STRING:
                    if ((length != strlen(ethermint_vc)) ||
                        (strncmp((char *) data, ethermint_vc, length) != 0)) {
                        PRINTF("Error: non standard verifyingContract\n");
                        return false;
                    }
                    break;
                default:
                    PRINTF("Error: unexpected type for verifyingContract (%u)!\n",
                           child->field->type);
                    return false;
            }
            memcpy(addr, data, length);
            explicit_bzero(addr + length, ADDRESS_LENGTH - length);
            return true;
        }
    }
    return false;
}

/**
 * Recursive helper for tree traversal. Visits node, then recurses on children if
 * VAL_STRUCT/VAL_ARRAY.
 * @return false if visitor returned false (abort), true otherwise
 */
static bool traverse_node(const s_struct_712_value *node, f_value_visitor visitor, void *context) {
    if (node == NULL) return true;

    // Visit this node
    if (!visitor(node, context)) return false;

    // Recurse on children for composite types
    if (node->kind == VAL_STRUCT || node->kind == VAL_ARRAY) {
        for (const s_struct_712_value *child = node->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if (!traverse_node(child, visitor, context)) return false;
        }
    }

    return true;
}

/**
 * Traverse domain value tree with visitor callback.
 */
bool impl_traverse_domain(f_value_visitor visitor, void *context) {
    if (visitor == NULL) return false;
    return traverse_node(g_impl.domain, visitor, context);
}

/**
 * Traverse message value tree with visitor callback.
 */
bool impl_traverse_message(f_value_visitor visitor, void *context) {
    if (visitor == NULL) return false;
    return traverse_node(g_impl.message, visitor, context);
}

bool impl_hash_pass(void) {
    return value_hash_pass(&g_impl);
}
