// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "psa/crypto.h"
#include "psa/error.h"
#include "psa_initial_attestation_api.h"
#include "simplem2mclient.h"
#include <mbedtls/base64.h>
#ifdef TARGET_LIKE_MBED
#include "mbed.h"
#endif
#include "application_init.h"
#include "mcc_common_button_and_led.h"

static void main_application(void);

int main(void) { return mcc_platform_run_program(main_application); }

// Pointers to the resources that will be created in main_application().
static M2MResource *attested_sensor_nonce_res;
static M2MResource *attested_sensor_value_res;

// Pointer to mbedClient, used for calling close function.
static SimpleM2MClient *client;

void notification_status_callback(const M2MBase &object,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType /*type*/) {
    switch (status) {
    case M2MBase::MESSAGE_STATUS_BUILD_ERROR:
        printf(
            "Message status callback: (%s) error when building CoAP message\n",
            object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_RESEND_QUEUE_FULL:
        printf("Message status callback: (%s) CoAP resend queue full\n",
               object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_SENT:
        printf("Message status callback: (%s) Message sent to server\n",
               object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_DELIVERED:
        printf("Message status callback: (%s) Message delivered\n",
               object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_SEND_FAILED:
        printf("Message status callback: (%s) Message sending failed\n",
               object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_SUBSCRIBED:
        printf("Message status callback: (%s) subscribed\n", object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_UNSUBSCRIBED:
        printf("Message status callback: (%s) subscription removed\n",
               object.uri_path());
        break;
    case M2MBase::MESSAGE_STATUS_REJECTED:
        printf(
            "Message status callback: (%s) server has rejected the message\n",
            object.uri_path());
        break;
    default:
        break;
    }
}

void print_buf(const char *label, const uint8_t *buf, uint32_t buf_sz) {
    printf("%s (@%p) (%lu bytes):\n", label, buf, buf_sz);
    for (uint32_t i = 0; i < buf_sz; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static bool set_resource(M2MResource *res, const uint8_t *token,
                         size_t token_sz) {
    print_buf("PSA token", token, token_sz);

    uint8_t buf[640];
    size_t encoded_sz;

    int rc =
        mbedtls_base64_encode(buf, sizeof buf, &encoded_sz, token, token_sz);

    switch (rc) {
    case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
        printf("destination buffer too small\n");
        return false;
    default:
        break;
    }

    res->set_value(buf, encoded_sz);

    return true;
}

void attest(const uint8_t *nonce, uint16_t nonce_sz) {
#define MAX_ATTESTATION_TOKEN_SIZE (0x200)
    psa_attest_err_t rc = PSA_ATTEST_ERR_SUCCESS;
    uint8_t t[MAX_ATTESTATION_TOKEN_SIZE] = {};
    uint32_t t_sz;

    printf("computing attestation resource\n");
    print_buf("nonce", nonce, nonce_sz);

    rc = psa_initial_attest_get_token_size(nonce_sz, &t_sz);
    if (rc != PSA_ATTEST_ERR_SUCCESS) {
        printf("Getting initial attestation token size failed with status %d\n",
               rc);
        return;
    }

    // XXX(tho) -- not sure about the semantics of the "token_size" argument to
    // psa_initial_attest_get_token(..., uint32_t *token_size).  I'd have
    // expected this to be a value-result argument that the caller uses to tell
    // the callee the size of memory allocated to the token buffer, and (on
    // success) the callee fills with the actual length of the produced token.
    // This doesn't seem to be the case though: in fact, if I pass: t_sz = 512;
    // the returned value is unchanged, while the token is effectively 438
    // bytes worth.
    // So, it looks like calling psa_initial_attest_get_token_size() is
    // necessary after all?
    rc = psa_initial_attest_get_token(nonce, nonce_sz, t, &t_sz);
    if (rc != PSA_ATTEST_ERR_SUCCESS) {
        printf("PSA attestation failed with status %d\n", rc);
        return;
    }

    (void)set_resource(attested_sensor_value_res, t, t_sz);
}

static bool extract_nonce(const uint8_t *b64, size_t b64_sz, uint8_t *nonce,
                          size_t *pnonce_sz) {
    size_t nonce_sz;

    printf("base64 nonce: %s\n", b64);

    switch (mbedtls_base64_decode(nonce, *pnonce_sz, &nonce_sz, b64, b64_sz)) {
    case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
        printf("nonce buffer too small\n");
        return false;
    case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
        printf("invalid base64\n");
        return false;
    }

    switch (nonce_sz) {
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32:
        break;
    default:
        printf("bad nonce size (%zu)\n", nonce_sz);
        return false;
    }

    *pnonce_sz = nonce_sz;

    return true;
}

static void attested_sensor_reading_callback(void *) {
    // clear previous result as soon as we receive a new request
    attested_sensor_value_res->set_value(NULL, 0);

    const uint8_t *nonce_b64 = attested_sensor_nonce_res->value();
    const size_t nonce_b64_sz = attested_sensor_nonce_res->value_length();

    // use the largest possible nonce size (64 bytes)
    uint8_t nonce[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
    size_t nonce_sz = sizeof nonce;

    if (!extract_nonce(nonce_b64, nonce_b64_sz, nonce, &nonce_sz)) {
        printf("Failed extracting nonce from PUT request\n");
        // XXX(tho) it looks like returning here leaves the resource in
        // confused state... Pelion needs to timeout before it can
        // request again.  TODO(tho) how do we send an error?
        return;
    }

    // TODO(tho) we should immediately ack because we don't know how long
    // will it take to respond with the token.  Is that taken care of
    // automatically by the API?

    attest(nonce, nonce_sz);
}

void main_application(void) {
#if defined(__linux__) && (MBED_CONF_MBED_TRACE_ENABLE == 0)
    // make sure the line buffering is on as non-trace builds do
    // not produce enough output to fill the buffer
    setlinebuf(stdout);
#endif

    // Initialize trace-library first
    if (application_init_mbed_trace() != 0) {
        printf("Failed initializing mbed trace\n");
        return;
    }

    // Initialize storage
    if (mcc_platform_storage_init() != 0) {
        printf("Failed to initialize storage\n");
        return;
    }

    // Initialize platform-specific components
    if (mcc_platform_init() != 0) {
        printf("ERROR - platform_init() failed!\n");
        return;
    }

    // Print platform information
    mcc_platform_sw_build_info();

    // Initialize network
    if (!mcc_platform_init_connection()) {
        printf("Network initialized, registering...\n");
    } else {
        return;
    }

    // SimpleClient is used for registering and unregistering resources to a
    // server.
    SimpleM2MClient mbedClient;

    // application_init() runs the following initializations:
    //  1. platform initialization
    //  2. print memory statistics if MBED_HEAP_STATS_ENABLED is defined
    //  3. FCC initialization.
    if (!application_init()) {
        printf("Initialization failed, exiting application!\n");
        return;
    }

    psa_status_t rc = psa_crypto_init();
    if (rc != PSA_SUCCESS) {
        printf("PSA crypto initialisation failed with status %ld, exiting "
               "application!\n",
               rc);
        return;
    }

    // Save pointer to mbedClient so that other functions can access it.
    client = &mbedClient;

    // register the attested sensor reading resources (nonce and value)
    attested_sensor_nonce_res = mbedClient.add_cloud_resource(
        33455, 0, 0, "attested_sensor_reading_nonce",
        M2MResourceInstance::OPAQUE, M2MBase::PUT_ALLOWED, "", false,
        (void *)attested_sensor_reading_callback, NULL);

    attested_sensor_value_res = mbedClient.add_cloud_resource(
        33455, 0, 1, "attested_sensor_reading_val", M2MResourceInstance::OPAQUE,
        M2MBase::GET_ALLOWED, NULL, true, NULL,
        (void *)notification_status_callback);

    mbedClient.register_and_connect();

    // Check if client is registering or registered, if true sleep and repeat.
    while (mbedClient.is_register_called()) {
        mcc_platform_do_wait(100);
    }

    // Client unregistered, disconnect and exit program.
    mcc_platform_close_connection();
}
