#include "app_mem_utils.h"
#include "mem_utils.h"
#include "type_hash.h"
#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "apdu_constants.h"  // APDU response codes
#include "typed_data.h"
#include "lists.h"

/**
 * Encode & hash the given structure field
 *
 * @param[in] field_ptr pointer to the struct field
 * @return \ref true it finished correctly, \ref false if it didn't (memory allocation)
 */
static bool encode_and_hash_field(const s_struct_712_field *field_ptr) {
    const char *name;

    if (!format_hash_field_type(field_ptr, (cx_hash_t *) &global_sha3)) {
        return false;
    }
    // space between field type name and field name
    hash_byte(' ', (cx_hash_t *) &global_sha3);

    // field name
    name = field_ptr->key_name;
    hash_nbytes((uint8_t *) name, strlen(name), (cx_hash_t *) &global_sha3);
    return true;
}

/**
 * Encode & hash the a given structure type
 *
 * @param[in] struct_ptr pointer to the structure we want the typestring of
 * @param[in] str_length length of the formatted string in memory
 * @return pointer of the string in memory, \ref NULL in case of an error
 */
static bool encode_and_hash_type(const s_struct_712 *struct_ptr) {
    const char *struct_name;
    const s_struct_712_field *field_ptr;

    // struct name
    struct_name = struct_ptr->name;
    hash_nbytes((uint8_t *) struct_name, strlen(struct_name), (cx_hash_t *) &global_sha3);

    // opening struct parentheses
    hash_byte('(', (cx_hash_t *) &global_sha3);

    for (field_ptr = struct_ptr->fields; field_ptr != NULL;
         field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
        // comma separating struct fields
        if (field_ptr != struct_ptr->fields) {
            hash_byte(',', (cx_hash_t *) &global_sha3);
        }

        if (encode_and_hash_field(field_ptr) == false) {
            return NULL;
        }
    }
    // closing struct parentheses
    hash_byte(')', (cx_hash_t *) &global_sha3);

    return true;
}

typedef struct struct_dep {
    flist_node_t _list;
    const s_struct_712 *s;
} s_struct_dep;

/**
 * Add a struct to the dependency list if not already present
 *
 * @param[in,out] first_dep pointer to the head of the dependency list
 * @param[in] struct_ptr pointer to the struct to add
 * @return \ref true on success, \ref false on memory allocation failure
 */
static bool add_dep_if_new(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    s_struct_dep *tmp;
    s_struct_dep *new_dep;

    for (tmp = *first_dep; tmp != NULL; tmp = (s_struct_dep *) ((flist_node_t *) tmp)->next) {
        if (tmp->s == struct_ptr) return true;
    }
    if ((new_dep = APP_MEM_ALLOC(sizeof(*new_dep))) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    new_dep->s = struct_ptr;
    flist_push_back((flist_node_t **) first_dep, (flist_node_t *) new_dep);
    return true;
}

/**
 * Scan all fields of a struct and add any unknown TYPE_STRUCT dependencies
 *
 * @param[in,out] first_dep pointer to the head of the dependency list
 * @param[in] struct_ptr pointer to the struct whose fields are scanned
 * @return \ref true on success, \ref false on error
 */
static bool collect_direct_deps(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    const s_struct_712_field *field_ptr;
    const s_struct_712 *dep;
    const char *dep_name;

    for (field_ptr = struct_ptr->fields; field_ptr != NULL;
         field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
        if (field_ptr->type == TYPE_STRUCT) {
            dep_name = get_struct_field_typename(field_ptr);
            if ((dep = get_structn(dep_name, strlen(dep_name))) == NULL) {
                PRINTF("Error: could not find EIP-712 dependency struct \"%s\" during type_hash\n",
                       dep_name);
                return false;
            }
            if (!add_dep_if_new(first_dep, dep)) {
                return false;
            }
        }
    }
    return true;
}

/**
 * Find all the transitive dependencies of a given structure
 *
 * Uses the dependency list itself as a worklist: new entries are appended at
 * the back while the cursor advances forward, so newly discovered dependencies
 * are processed without recursion and without extra allocations.
 *
 * @param[out] first_dep pointer to the head of the dependency list
 * @param[in] struct_ptr pointer to the struct we are getting the dependencies of
 * @return \ref true on success, \ref false on error
 */
static bool get_struct_dependencies(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    s_struct_dep *cursor;

    if (!collect_direct_deps(first_dep, struct_ptr)) {
        return false;
    }

    for (cursor = *first_dep; cursor != NULL;
         cursor = (s_struct_dep *) ((flist_node_t *) cursor)->next) {
        if (!collect_direct_deps(first_dep, cursor->s)) {
            return false;
        }
    }
    return true;
}

static bool compare_struct_deps(const s_struct_dep *a, const s_struct_dep *b) {
    const char *name1, *name2;
    size_t namelen1, namelen2;
    int str_cmp_result;

    name1 = a->s->name;
    namelen1 = strlen(name1);
    name2 = b->s->name;
    namelen2 = strlen(name2);

    str_cmp_result = strncmp(name1, name2, MIN(namelen1, namelen2));
    if ((str_cmp_result > 0) || ((str_cmp_result == 0) && (namelen1 > namelen2))) {
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_struct_dep(s_struct_dep *sdep) {
    APP_MEM_FREE(sdep);
}

static bool type_hash_internal(const char *struct_name,
                               const uint8_t struct_name_length,
                               uint8_t *hash_buf,
                               s_struct_dep **deps) {
    const void *struct_ptr;

    if ((struct_ptr = get_structn(struct_name, struct_name_length)) == NULL) {
        PRINTF("Error: could not find EIP-712 struct \"");
        for (int i = 0; i < struct_name_length; ++i) PRINTF("%c", struct_name[i]);
        PRINTF("\" for type_hash\n");
        return false;
    }
    if (cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) {
        return false;
    }
    // get_struct_dependencies may populate `deps` partially before failing;
    // every exit path past this point must release the list.
    if (!get_struct_dependencies(deps, struct_ptr)) {
        return false;
    }
    flist_sort((flist_node_t **) deps, (f_list_node_cmp) &compare_struct_deps);
    if (encode_and_hash_type(struct_ptr) == false) {
        return false;
    }
    // loop over each struct and generate string
    for (const s_struct_dep *tmp = *deps; tmp != NULL;
         tmp = (s_struct_dep *) ((flist_node_t *) tmp)->next) {
        if (encode_and_hash_type(tmp->s) == false) {
            return false;
        }
    }

    // copy hash into memory
    if (finalize_hash((cx_hash_t *) &global_sha3, hash_buf, KECCAK256_HASH_BYTESIZE) != true) {
        return false;
    }
    return true;
}

/**
 * Encode the structure's type and hash it
 *
 * @param[in] struct_name name of the given struct
 * @param[in] struct_name_length length of the name of the given struct
 * @param[out] hash_buf buffer containing the resulting type_hash
 * @return whether the type_hash was successful or not
 */
bool type_hash(const char *struct_name, const uint8_t struct_name_length, uint8_t *hash_buf) {
    s_struct_dep *deps = NULL;
    bool ret;

    ret = type_hash_internal(struct_name, struct_name_length, hash_buf, &deps);
    flist_clear((flist_node_t **) &deps, (f_list_node_del) &delete_struct_dep);
    return ret;
}
