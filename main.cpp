// ----------------------------------------------------------------------------
// Copyright 2016-2020 ARM Ltd.
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

#include "application_init.h"
#include "mbed.h"
#include "mcc_common_button_and_led.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include "psa_attest_inject_key.h"
#include "psa_initial_attestation_api.h"
#include "simplem2mclient.h"
#include <mbedtls/base64.h>

extern "C" {
#include "mbed-os/components/TARGET_PSA/services/attestation/qcbor/inc/UsefulBuf.h"
#include "mbed-os/components/TARGET_PSA/services/attestation/qcbor/inc/qcbor.h"
#include "mbed-os/components/TARGET_PSA/services/attestation/qcbor/inc/useful_buf.h"
}

static const uint8_t pri_key[] = {
    0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56, 0x38, 0xc4, 0x31,
    0xcf, 0x1d, 0xf1, 0xc9, 0x94, 0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4,
    0xfd, 0x43, 0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee};

static void main_application(void);

int main(void) { return mcc_platform_run_program(main_application); }

// Pointers to the resources that will be created in main_application().
static M2MResource *attested_sensor_nonce_res;
static M2MResource *attested_sensor_value_res;
static M2MResource *exec_attested_sensor_res;

static void print_buf(const char *label, const uint8_t *buf, uint32_t buf_sz) {
    printf("%s (@%p) (%lu bytes):\n", label, buf, buf_sz);

    for (uint32_t i = 0; i < buf_sz; i++)
        printf("%02x", buf[i]);

    printf("\n");
}

static bool psa_init(void) {
    psa_status_t rc = psa_crypto_init();
    if (rc != PSA_SUCCESS) {
        printf("psa_crypto_init() failed with status %ld\n", rc);
        return false;
    }

    uint8_t pub_key[65];
    unsigned int pub_key_sz = 0;

    rc = psa_attestation_inject_key(
        pri_key, sizeof pri_key,
        PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1), pub_key,
        sizeof pub_key, &pub_key_sz);

    switch (rc) {
    case PSA_SUCCESS:
        print_buf("IAK pub", pub_key, pub_key_sz);
    case PSA_ERROR_OCCUPIED_SLOT:
        // It's OK if the key already exist (it means we've already been here)
        break;
    default:
        printf("psa_attestation_inject_key() failed with status %ld\n", rc);
        return false;
    }

    return true;
}

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

static bool set_resource(M2MResource *res, const uint8_t *bin, size_t bin_sz) {
    print_buf("resource", bin, bin_sz);

    uint8_t b64[1024];
    size_t b64_sz;

    int rc = mbedtls_base64_encode(b64, sizeof b64, &b64_sz, bin, bin_sz);

    switch (rc) {
    case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
        printf("destination buffer too small\n");
        return false;
    default:
        break;
    }

    res->set_value(b64, b64_sz);

    return true;
}

static bool mix(unsigned int s, const uint8_t *T, size_t T_sz,
                uint8_t out[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32]) {
    char sbuf[64] = {0};
    mbedtls_sha256_context c;

    if (snprintf(sbuf, sizeof sbuf, "%u", s) < 0) {
        return false;
    }

    printf("s=%s\n", sbuf);

    mbedtls_sha256_init(&c);

    if (mbedtls_sha256_starts_ret(&c, 0) || // bizarrely, 0 means SHA-256
        mbedtls_sha256_update_ret(&c, (const uint8_t *)sbuf, strlen(sbuf)) ||
        mbedtls_sha256_update_ret(&c, T, T_sz) ||
        mbedtls_sha256_finish_ret(&c, out)) {
        return false;
    }

    return true;
}

// CBOR-encode the attested-reading resource:
// attested-reading = {
//    s : uint,
//    T : bstr
// }
static bool cbor_it(unsigned int s, const uint8_t *token, size_t token_sz,
                    UsefulBufC *pcbor) {
    QCBOREncodeContext cbor_ctx;
    static uint8_t buf[1024];

    QCBOREncode_Init(&cbor_ctx, UsefulBuf_FROM_BYTE_ARRAY(buf));
    QCBOREncode_OpenArray(&cbor_ctx);
    QCBOREncode_AddUInt64(&cbor_ctx, s);
    QCBOREncode_AddBytes(&cbor_ctx, ((UsefulBufC){token, token_sz}));
    QCBOREncode_CloseArray(&cbor_ctx);

    if (QCBOREncode_Finish(&cbor_ctx, pcbor)) {
        printf("encoding CBOR resource failed\n");
        return false;
    }

    return true;
}

static void attested_sensor_reading(M2MResource *res, const uint8_t *ch,
                                    uint16_t ch_sz) {
    psa_attest_err_t rc = PSA_ATTEST_ERR_SUCCESS;
    uint8_t T[512], nonce[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32];
    uint32_t T_sz;
    static unsigned int s;

    printf("computing attested sensor reading\n");
    printf("ch_sz=%zu\n", ch_sz);
    print_buf("ch", ch, ch_sz);

    if (!mix(++s, ch, ch_sz, nonce)) {
        printf("computing mix() failed\n");
        return;
    }

    print_buf("computed nonce=mix(s, ch)", nonce, sizeof nonce);

    rc = psa_initial_attest_get_token_size(sizeof nonce, &T_sz);
    if (rc != PSA_ATTEST_ERR_SUCCESS) {
        printf("Getting initial attestation token size failed with status %d\n",
               rc);
        return;
    }

    if (T_sz > sizeof T) {
        printf("token would exceed allocated memory\n");
        return;
    }

    rc = psa_initial_attest_get_token(nonce, sizeof nonce, T, &T_sz);
    if (rc != PSA_ATTEST_ERR_SUCCESS) {
        printf("PSA attestation failed with status %d\n", rc);
        return;
    }

    UsefulBufC cbor;

    // Encode aggregate resource
    // attested-reading = { s : uint, T : bstr }
    if (!cbor_it(s, T, T_sz, &cbor)) {
        printf("CBOR encoding\n");
        return;
    }

    (void)set_resource(res, (const uint8_t *)cbor.ptr, cbor.len);
}

// Extract base64 encoded challenge into the supplied binary buffer
static bool extract_ch(const uint8_t *b64, size_t b64_sz, uint8_t *bin,
                       size_t *pbin_sz) {
    size_t bin_sz;

    print_buf("ch", b64, b64_sz);

    switch (mbedtls_base64_decode(bin, *pbin_sz, &bin_sz, b64, b64_sz)) {
    case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
        printf("nonce buffer too small\n");
        return false;
    case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
        printf("invalid base64\n");
        return false;
    }

    *pbin_sz = bin_sz;

    return true;
}

static void attested_sensor_reading_callback(void *) {
    // clear previous result as soon as we receive a new request
    attested_sensor_value_res->set_value(NULL, 0);

    attested_sensor_reading(attested_sensor_value_res,
                            attested_sensor_nonce_res->value(),
                            attested_sensor_nonce_res->value_length());
}

// Extract challenge from Execute parameters
// Expects "ch=<value>"
static bool extract_ch_from_exec_params(const uint8_t *args, uint16_t args_sz,
                                        uint8_t *bin, size_t *pbin_sz) {
    const char *ch_key = "ch=";

    print_buf("args", args, args_sz);

    if (memcmp(args, (const void *)ch_key, strlen(ch_key)) != 0) {
        printf("no ch key\n");
        return false;
    }

    if (args_sz <= strlen(ch_key)) {
        printf("no ch value\n");
        return false;
    }

    bin = (uint8_t *)args + strlen(ch_key);
    *pbin_sz = args_sz - strlen(ch_key);

    return true;
}

static void exec_attested_res_callback(void *args) {
    exec_attested_sensor_res->set_value(NULL, 0);

    if (args) {
        M2MResource::M2MExecuteParameter *params =
            (M2MResource::M2MExecuteParameter *)args;

        // use the largest possible nonce size (64 bytes)
        uint8_t nonce[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
        size_t nonce_sz = sizeof nonce;

        if (!extract_ch_from_exec_params(params->get_argument_value(),
                                         params->get_argument_value_length(),
                                         nonce, &nonce_sz)) {
            printf("Failed extracting nonce from Execute arguments\n");
            return;
        }

        attested_sensor_reading(exec_attested_sensor_res, nonce, nonce_sz);

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
        printf("mcc_platform_init() failed\n");
        return false;
    }

    mcc_platform_sw_build_info();

    if (mcc_platform_init_connection() == -1) {
        printf("Failed to initialize connection\n");
        return false;
    }

    printf("Network initialized\n");

    if (!application_init()) {
        printf("application_init() failed\n");
        return false;
    }

    return true;
}

static void do_register_resources(SimpleM2MClient &mbed_client) {
    // asynchronous:
    //  /33455/0/0 -> nonce
    //  /33455/0/1 -> value
    // synchronous:
    //  /33455/0/2
    attested_sensor_nonce_res = mbed_client.add_cloud_resource(
        33455, 0, 0, "attested_sensor_reading_nonce",
        M2MResourceInstance::OPAQUE, M2MBase::PUT_ALLOWED, "", false,
        (void *)attested_sensor_reading_callback, NULL);

    attested_sensor_value_res = mbed_client.add_cloud_resource(
        33455, 0, 1, "attested_sensor_reading_val", M2MResourceInstance::OPAQUE,
        M2MBase::GET_ALLOWED, NULL, true, NULL,
        (void *)notification_status_callback);

    exec_attested_sensor_res = mbed_client.add_cloud_resource(
        33455, 0, 2, "exec_attested_sensor", M2MResourceInstance::OPAQUE,
        M2MBase::GET_POST_ALLOWED, NULL, true,
        (void *)exec_attested_res_callback,
        (void *)notification_status_callback);

    exec_attested_sensor_res->set_delayed_response(true);

    mbed_client.register_and_connect();
}

static void main_application(void) {
    if (!psa_init() || !do_init()) {
        printf("Initalization failed, exiting application\n");
        return;
    }

    // SimpleClient is used for registering and unregistering resources to a
    // server.
    SimpleM2MClient mbedClient;

    do_register_resources(mbedClient);

    // Check if client is registering or registered, if true sleep and repeat.
    while (mbedClient.is_register_called()) {
        mcc_platform_do_wait(100);
    }

    // Client unregistered, disconnect and exit program.
    mcc_platform_close_connection();
}
