#pragma once

#include <stdbool.h>
#include "typed_data.h"

/**
 * Run the hash pass over the complete EIP-712 value tree.
 *
 * Computes hashStruct(domain) and hashStruct(message) via recursive traversal
 * and writes results to tmpCtx.messageSigningContext712.domainHash and .messageHash.
 * Also extracts domain special fields (chainId, verifyingContract) into eip712_context.
 *
 * Must be called only after impl_is_complete() returns true.
 *
 * @return whether the hash pass was successful
 */
bool value_hash_pass(const s_eip712_impl *impl);
