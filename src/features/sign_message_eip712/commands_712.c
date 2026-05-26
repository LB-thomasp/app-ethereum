#include "apdu_constants.h"  // APDU response codes
#include "context_712.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "schema_hash.h"
#include "filtering.h"
#include "common_ui.h"  // ui_idle, ui_error_blind_signing
#include "manage_asset_info.h"
#include "tx_ctx.h"  // get_tx_ctx_count
#include "value_hash.h"
#include "common_712.h"  // ui_712_start

// APDUs P1
#define P1_COMPLETE  0x00
#define P1_PARTIAL   0xFF
#define P1_DISCARDED 0x01

// APDUs P2
#define P2_DEF_NAME               0x00
#define P2_DEF_FIELD              0xFF
#define P2_IMPL_NAME              P2_DEF_NAME
#define P2_IMPL_ARRAY             0x0F
#define P2_IMPL_FIELD             P2_DEF_FIELD
#define P2_FILT_ACTIVATE          0x00
#define P2_FILT_DISCARDED_PATH    0x01
#define P2_FILT_MESSAGE_INFO      0x0F
#define P2_FILT_CALLDATA_SPENDER  0xF4
#define P2_FILT_CALLDATA_AMOUNT   0xF5
#define P2_FILT_CALLDATA_SELECTOR 0xF6
#define P2_FILT_CALLDATA_CHAIN_ID 0xF7
#define P2_FILT_CALLDATA_CALLEE   0xF8
#define P2_FILT_CALLDATA_VALUE    0xF9
#define P2_FILT_CALLDATA_INFO     0xFA
#define P2_FILT_CONTRACT_NAME     0xFB
#define P2_FILT_DATE_TIME         0xFC
#define P2_FILT_AMOUNT_JOIN_TOKEN 0xFD
#define P2_FILT_AMOUNT_JOIN_VALUE 0xFE
#define P2_FILT_RAW_FIELD         0xFF

/**
 * Send the response to the previous APDU command
 *
 * In case of an error it uses the global variable to retrieve the error code and resets
 * the app context
 *
 * @param[in] success whether the command was successful
 */
static void apdu_reply(bool success) {
    bool home = true;

    if (success) {
        apdu_response_code = SWO_SUCCESS;
    } else {
        if (apdu_response_code == SWO_SUCCESS) {  // somehow not set
            apdu_response_code = SWO_PARAMETER_ERROR_NO_INFO;
        }
        if (eip712_context != NULL) {
            home = eip712_context->go_home_on_failure;
        }
        eip712_context_deinit();
        if (home) ui_idle();
    }
}

/**
 * Send the response to the previous APDU command
 *
 * In case of an error it uses the global variable to retrieve the error code and resets
 * the app context
 *
 * @param[in] success whether the command was successful
 */
void handle_eip712_return_code(bool success) {
    apdu_reply(success);

    io_seproxyhal_send_status(apdu_response_code, 0, false, false);
}

/**
 * Process the EIP712 struct definition command
 *
 * @param[in] p2 instruction parameter 2
 * @param[in] cdata command data
 * @param[in] length length of the command data
 * @return whether the command was successful or not
 */
uint16_t handle_eip712_struct_def(uint8_t p2, const uint8_t *cdata, uint8_t length) {
    bool ret = true;

    if (eip712_context == NULL) {
        ret = eip712_context_init();
    }
    if (struct_state == DEFINED) {
        ret = false;
    }

    if (ret) {
        switch (p2) {
            case P2_DEF_NAME:
                ret = set_struct_name(length, cdata);
                break;
            case P2_DEF_FIELD:
                ret = set_struct_field(length, cdata);
                break;
            default:
                PRINTF("Unknown P2 0x%x\n", p2);
                apdu_response_code = SWO_WRONG_P1_P2;
                ret = false;
        }
    }
    apdu_reply(ret);
    return apdu_response_code;
}

/**
 * Process the EIP712 struct implementation command
 *
 * @param[in] p1 instruction parameter 1
 * @param[in] p2 instruction parameter 2
 * @param[in] cdata command data
 * @param[in] length length of the command data
 * @return whether the command was successful or not
 */
uint16_t handle_eip712_struct_impl(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length) {
    bool ret = false;

    if (eip712_context == NULL) {
        apdu_response_code = SWO_COMMAND_NOT_ALLOWED;
    } else {
        switch (p2) {
            case P2_IMPL_NAME:
                ret = impl_set_root((char *) cdata, length);
                if (ret) {
                    struct_state = DEFINED;
                    ui_712_field_flags_reset();
                }
                break;

            case P2_IMPL_FIELD: {
                const s_struct_712_field *cur_field = impl_get_current_field();
                const s_struct_712_value *leaf = impl_add_field(cdata, length, p1 != P1_COMPLETE);
                ret = (leaf != NULL);
                if (ret && (cur_field != NULL) && (p1 == P1_COMPLETE)) {
                    ret = ui_712_accumulate_value(cur_field, leaf->data, leaf->length);
                }
                break;
            }

            case P2_IMPL_ARRAY:
                if (length != 1) {
                    apdu_response_code = SWO_INCORRECT_DATA;
                } else {
                    ret = impl_new_array(cdata[0]);
                }
                break;

            default:
                PRINTF("Unknown P2 0x%x\n", p2);
                apdu_response_code = SWO_WRONG_P1_P2;
        }
    }
    apdu_reply(ret);
    return apdu_response_code;
}

/**
 * Process the EIP712 filtering command
 *
 * @param[in] p1 instruction parameter 1
 * @param[in] p2 instruction parameter 2
 * @param[in] cdata command data
 * @param[in] length length of the command data
 * @return whether the command was successful or not
 */
uint16_t handle_eip712_filtering(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length) {
    bool ret = true;
    bool reply_apdu = true;
    uint32_t path_crc = 0;

    if (eip712_context == NULL) {
        apdu_reply(false);
        return SWO_COMMAND_NOT_ALLOWED;
    }
    if ((p2 != P2_FILT_ACTIVATE) && (ui_712_get_filtering_mode() != EIP712_FILTERING_FULL)) {
        return SWO_SUCCESS;
    }
    switch (p2) {
        case P2_FILT_ACTIVATE:
            if (!N_storage.verbose_eip712) {
                ret = compute_schema_hash(eip712_context->schema_hash);
                if (ret) {
                    // Switch to filtering mode and lock the type system in
                    // one atomic step: a host cannot append struct
                    // definitions after the hash is fixed and so cannot sign
                    // a message whose schema differs from the one the hash
                    // covered. On hash-compute failure, both state changes
                    // are skipped so the activate can be retried.
                    ui_712_set_filtering_mode(EIP712_FILTERING_FULL);
                    struct_state = DEFINED;
                }
            }
            forget_known_assets();
            break;
        case P2_FILT_DISCARDED_PATH:
            ret = filtering_discarded_path(cdata, length);
            break;
        case P2_FILT_MESSAGE_INFO:
            ret = filtering_message_info(cdata, length);
            if (ret) {
                reply_apdu = false;
            }
            break;
        case P2_FILT_CALLDATA_SPENDER:
            ret = filtering_calldata_spender(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_AMOUNT:
            ret = filtering_calldata_amount(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_SELECTOR:
            ret = filtering_calldata_selector(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_CHAIN_ID:
            ret = filtering_calldata_chain_id(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_CALLEE:
            ret = filtering_calldata_callee(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_VALUE:
            ret = filtering_calldata_value(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_CALLDATA_INFO:
            ret = filtering_calldata_info(cdata, length);
            break;
        case P2_FILT_CONTRACT_NAME:
            ret = filtering_trusted_name(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_DATE_TIME:
            ret = filtering_date_time(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_AMOUNT_JOIN_TOKEN:
            ret = filtering_amount_join_token(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_AMOUNT_JOIN_VALUE:
            ret = filtering_amount_join_value(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        case P2_FILT_RAW_FIELD:
            ret = filtering_raw_field(cdata, length, p1 == P1_DISCARDED, &path_crc);
            break;
        default:
            PRINTF("Unknown P2 0x%x\n", p2);
            apdu_response_code = SWO_WRONG_P1_P2;
            ret = false;
    }
    if ((p2 > P2_FILT_MESSAGE_INFO) && (p2 != P2_FILT_CALLDATA_INFO) && ret) {
        if (!ui_712_push_new_filter_path(path_crc)) {
            ret = false;
        }
    }
    if (reply_apdu) {
        apdu_reply(ret);
        return apdu_response_code;
    }
    return SWO_NO_RESPONSE;
}

/**
 * Process the EIP712 sign command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
uint16_t handle_eip712_sign(const uint8_t *cdata, uint8_t length) {
    bool ret = false;

    if (eip712_context == NULL) {
        apdu_response_code = SWO_COMMAND_NOT_ALLOWED;
    } else if (!impl_is_complete()) {
        PRINTF("impl not complete\n");
        apdu_response_code = SWO_INCORRECT_DATA;
    } else if (!impl_hash_pass()) {
        PRINTF("value_hash_pass failed\n");
    } else if ((ui_712_get_filtering_mode() == EIP712_FILTERING_FULL) &&
               (!ui_712_message_info_received() || (ui_712_remaining_filters() != 0))) {
        PRINTF("%d EIP712 filters are missing\n", ui_712_remaining_filters());
        apdu_response_code = SWO_REFERENCED_DATA_NOT_FOUND;
    } else if (!all_calldata_info_processed() || (get_tx_ctx_count() != 0)) {
        PRINTF("Unprocessed calldata\n");
        apdu_response_code = SWO_REFERENCED_DATA_NOT_FOUND;
    } else if (parseBip32(cdata, &length, &tmpCtx.messageSigningContext.bip32) == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
    } else {
        // In the new value-tree architecture impl APDUs never trigger display, so appState is
        // not yet APP_STATE_SIGNING_EIP712. Enforce blind-signing protection and transition
        // to signing state here (the old streaming code did this on the first field display).
        if ((ui_712_get_filtering_mode() == EIP712_FILTERING_BASIC) && !N_storage.dataAllowed &&
            !N_storage.verbose_eip712) {
            ui_error_blind_signing();
            apdu_response_code = SWO_INCORRECT_DATA;
            eip712_context->go_home_on_failure = false;
        } else {
            bool should_start_ui = true;

            // Only call ui_712_start() if not already in signing state (FULL filtering
            // with filtering APDUs may have already transitioned appState via display).
            if (appState != APP_STATE_SIGNING_EIP712) {
                // For verbose/no-filtering mode, populate UI pairs from value tree before starting
                // UI
                if (ui_712_get_filtering_mode() == EIP712_FILTERING_BASIC) {
                    if (!ui_712_populate_from_value_tree()) {
                        PRINTF("ui_712_populate_from_value_tree failed\n");
                        apdu_response_code = SWO_INCORRECT_DATA;
                        should_start_ui = false;
                    }
                }
                if (should_start_ui) {
                    apdu_response_code = ui_712_start(ui_712_get_filtering_mode());
                }
            }
            if (should_start_ui && (apdu_response_code == SWO_SUCCESS)) {
                ret = true;
#ifndef SCREEN_SIZE_WALLET
                if (!N_storage.verbose_eip712 &&
                    (ui_712_get_filtering_mode() == EIP712_FILTERING_BASIC)) {
                    ret = ui_712_message_hash();
                }
#endif
                ui_712_end_sign();
            } else if (apdu_response_code != SWO_SUCCESS) {
                PRINTF("SIGN fail: ui_712_start code=0x%04x\n", apdu_response_code);
            }
        }
    }

    if (!ret) {
        apdu_reply(false);
        return apdu_response_code;
    }
    return SWO_NO_RESPONSE;
}
