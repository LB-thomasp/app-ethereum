#include "context_712.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "sol_typenames.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "shared_context.h"  // reset_app_context
#include "common_ui.h"       // ui_idle

s_eip712_context *eip712_context = NULL;
uint16_t apdu_response_code;

/**
 * Initialize the EIP712 context
 *
 * @return a boolean indicating if the initialization was successful or not
 */
bool eip712_context_init(void) {
    if (eip712_context != NULL) {
        eip712_context_deinit();
        return false;
    }

    // init global variables
    if (APP_MEM_CALLOC((void **) &eip712_context, sizeof(*eip712_context)) == false) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    if (sol_typenames_init() == false) {
        return false;
    }

    if (ui_712_init() == false) {
        return false;
    }

    if (typed_data_init() == false) {
        return false;
    }

    eip712_context->go_home_on_failure = true;

    return true;
}

/**
 * De-initialize the EIP712 context
 */
void eip712_context_deinit(void) {
    typed_data_deinit();
    ui_712_deinit();
    sol_typenames_deinit();
    APP_MEM_FREE_AND_NULL((void **) &eip712_context);
    reset_app_context();
}
