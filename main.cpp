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
static M2MResource *exec_attested_sensor_res;

static void
notification_status_callback(const M2MBase &object,
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

static void print_buf(const char *label, const uint8_t *buf, uint32_t buf_sz) {
    printf("%s (@%p) (%lu bytes):\n", label, buf, buf_sz);
    for (uint32_t i = 0; i < buf_sz; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static bool set_resource(M2MResource *res, const uint8_t *token,
                         size_t token_sz) {
    print_buf("PSA token", token, token_sz);

    uint8_t buf[1024];
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

static bool M(unsigned int s, const uint8_t *T, size_t T_sz,
              uint8_t out[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32]) {
    char sbuf[64] = {0};
    mbedtls_sha256_context c;

    if (snprintf(sbuf, sizeof sbuf, "%u", s) < 0) {
        return false;
    }

    mbedtls_sha256_init(&c);

    if (mbedtls_sha256_starts_ret(&c, 0) || // bizarrely, 0 means SHA-256
        mbedtls_sha256_update_ret(&c, (const uint8_t *)sbuf, strlen(sbuf)) ||
        mbedtls_sha256_update_ret(&c, T, T_sz) ||
        mbedtls_sha256_finish_ret(&c, out)) {
        return false;
    }

    return true;
}

static void attest(M2MResource *res, const uint8_t *challenge,
                   uint16_t challenge_sz) {
#define MAX_ATTESTATION_TOKEN_SIZE (0x200)
    psa_attest_err_t rc = PSA_ATTEST_ERR_SUCCESS;
    uint8_t t[MAX_ATTESTATION_TOKEN_SIZE] = {};
    uint32_t t_sz;

    printf("computing attestation resource\n");
    print_buf("challenge", challenge, challenge_sz);

    static unsigned int s = 0;
    uint8_t nonce[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32];

    if (!M(s++, challenge, challenge_sz, nonce)) {
        printf("computing M() failed\n");
        return;
    }

    rc = psa_initial_attest_get_token_size(sizeof nonce, &t_sz);
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
    rc = psa_initial_attest_get_token(nonce, sizeof nonce, t, &t_sz);
    if (rc != PSA_ATTEST_ERR_SUCCESS) {
        printf("PSA attestation failed with status %d\n", rc);
        return;
    }

    // TODO(tho) compute aggregate resource {s, T}

    (void)set_resource(res, t, t_sz);
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

    attest(attested_sensor_value_res, nonce, nonce_sz);
}

static bool extract_nonce_from_exec_params(const uint8_t *args,
                                           uint16_t args_sz, uint8_t *nonce,
                                           uint16_t *pnonce_sz) {
    const char *nonce_key = "nonce=";
    uint16_t nonce_sz;

    print_buf("args", args, args_sz);

    if (memcmp(args, (const void *)nonce_key, strlen(nonce_key)) != 0) {
        printf("no nonce key\n");
        return false;
    }

    if (args_sz < strlen(nonce_key)) {
        printf("no nonce\n");
        return false;
    }

    nonce_sz = args_sz - strlen(nonce_key);

    switch (nonce_sz) {
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32:
        break;
    default:
        printf("bad nonce size (%zu)\n", nonce_sz);
        return false;
    }

    if (nonce_sz < *pnonce_sz) {
        printf("not enough space in the supplied buffer\n");
        return false;
    }

    memcpy(nonce, args + strlen(nonce_key), nonce_sz);

    return true;
}

static void exec_attested_res_callback(void *args) {
    exec_attested_sensor_res->set_value(NULL, 0);

    if (args) {
        M2MResource::M2MExecuteParameter *params =
            (M2MResource::M2MExecuteParameter *)args;

        // use the largest possible nonce size (64 bytes)
        uint8_t nonce[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
        uint16_t nonce_sz = sizeof nonce;

        if (!extract_nonce_from_exec_params(params->get_argument_value(),
                                            params->get_argument_value_length(),
                                            nonce, &nonce_sz)) {
            printf("Failed extracting nonce from Execute arguments\n");
            return;
        }

        attest(exec_attested_sensor_res, nonce, nonce_sz);

        exec_attested_sensor_res->send_delayed_post_response();
    }
}

static bool do_init(void) {
    if (application_init_mbed_trace() != 0) {
        printf("Failed initializing mbed trace\n");
        return false;
    }

    if (mcc_platform_storage_init() != 0) {
        printf("Failed to initialize storage\n");
        return false;
    }

    if (mcc_platform_init() != 0) {
        printf("mcc_platform_init() failed!\n");
        return false;
    }

    mcc_platform_sw_build_info();

    if (mcc_platform_init_connection() == -1) {
        printf("Failed to initialize connection\n");
        return false;
    }

    printf("Network initialized.\n");

    if (!application_init()) {
        printf("application_init() failed!\n");
        return false;
    }

    return true;
}

static void main_application(void) {
    if (!do_init()) {
        printf("Initalization failed, exiting application!\n");
        return;
    }

    psa_status_t rc = psa_crypto_init();
    if (rc != PSA_SUCCESS) {
        printf("PSA crypto initialization failed with status %ld, exiting "
               "application!\n",
               rc);
        return;
    }

    // SimpleClient is used for registering and unregistering resources to a
    // server.
    SimpleM2MClient mbedClient;

    attested_sensor_nonce_res = mbedClient.add_cloud_resource(
        33455, 0, 0, "attested_sensor_reading_nonce",
        M2MResourceInstance::OPAQUE, M2MBase::PUT_ALLOWED, "", false,
        (void *)attested_sensor_reading_callback, NULL);

    attested_sensor_value_res = mbedClient.add_cloud_resource(
        33455, 0, 1, "attested_sensor_reading_val", M2MResourceInstance::OPAQUE,
        M2MBase::GET_ALLOWED, NULL, true, NULL,
        (void *)notification_status_callback);

    exec_attested_sensor_res = mbedClient.add_cloud_resource(
        33455, 0, 2, "exec_attested_sensor", M2MResourceInstance::OPAQUE,
        M2MBase::GET_POST_ALLOWED, NULL, true,
        (void *)exec_attested_res_callback,
        (void *)notification_status_callback);

    exec_attested_sensor_res->set_delayed_response(true);

    mbedClient.register_and_connect();

    // Check if client is registering or registered, if true sleep and repeat.
    while (mbedClient.is_register_called()) {
        mcc_platform_do_wait(100);
    }

    // Client unregistered, disconnect and exit program.
    mcc_platform_close_connection();
}
