#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "utils/test_setup.h"
#include <snowflake/tls_policy.h>

#ifdef _WIN32
typedef SOCKET tls_socket_t;
#define TLS_SOCKET_BAD(sock) ((sock) == INVALID_SOCKET)
#else
typedef int tls_socket_t;
#define TLS_SOCKET_BAD(sock) ((sock) < 0)
#endif

static void close_tls_socket(tls_socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

typedef struct tls_env_backup {
    int had_ciphers;
    int had_min_version;
    char ciphers[4096];
    char min_version[128];
} tls_env_backup;

static int setup_tls_env(void **state) {
    tls_env_backup *backup = (tls_env_backup *) calloc(1, sizeof(*backup));
    const char *ciphers;
    const char *min_version;
    if (backup == NULL) {
        return -1;
    }
    ciphers = getenv(SNOWFLAKE_TLS_CIPHERS_ENV);
    min_version = getenv(SNOWFLAKE_MIN_TLS_VERSION_ENV);
    if (ciphers != NULL) {
        backup->had_ciphers = 1;
        snprintf(backup->ciphers, sizeof(backup->ciphers), "%s", ciphers);
    }
    if (min_version != NULL) {
        backup->had_min_version = 1;
        snprintf(backup->min_version, sizeof(backup->min_version), "%s", min_version);
    }
    sf_unsetenv(SNOWFLAKE_TLS_CIPHERS_ENV);
    sf_unsetenv(SNOWFLAKE_MIN_TLS_VERSION_ENV);
    *state = backup;
    return 0;
}

static int teardown_tls_env(void **state) {
    tls_env_backup *backup = (tls_env_backup *) *state;
    if (backup->had_ciphers) {
        sf_setenv(SNOWFLAKE_TLS_CIPHERS_ENV, backup->ciphers);
    } else {
        sf_unsetenv(SNOWFLAKE_TLS_CIPHERS_ENV);
    }
    if (backup->had_min_version) {
        sf_setenv(SNOWFLAKE_MIN_TLS_VERSION_ENV, backup->min_version);
    } else {
        sf_unsetenv(SNOWFLAKE_MIN_TLS_VERSION_ENV);
    }
    free(backup);
    return 0;
}

static void assert_connect_rejects(const char *fragment) {
    SF_CONNECT *sf = snowflake_init();
    SF_STATUS status;
    char message[512];
    assert_non_null(sf);
    status = snowflake_connect(sf);
    snprintf(message, sizeof(message), "%s", sf->error.msg != NULL ? sf->error.msg : "");
    snowflake_term(sf);
    assert_int_equal(status, SF_STATUS_ERROR_BAD_CONNECTION_PARAMS);
    assert_non_null(strstr(message, fragment));
}

static void test_blank_cipher_list_is_unset(void **unused) {
    sf_tls_policy_result policy;
    char error[512];
    (void) unused;
    assert_int_equal(sf_tls_policy_from_values("", NULL, &policy, error, sizeof(error)),
                     SF_STATUS_SUCCESS);
    assert_int_equal(policy.tls12.restricted, 0);
    assert_int_equal(policy.tls13.restricted, 0);
    assert_int_equal(policy.min_version, 0);
    assert_int_equal(sf_tls_policy_from_values("   ", NULL, &policy, error, sizeof(error)),
                     SF_STATUS_SUCCESS);
    assert_int_equal(policy.tls12.restricted, 0);
    assert_int_equal(policy.tls13.restricted, 0);
}

static void test_cipher_separators_only_fail(void **unused) {
    sf_tls_policy_result policy;
    char error[512];
    (void) unused;
    assert_int_equal(sf_tls_policy_from_values(": :", NULL, &policy, error, sizeof(error)),
                     SF_STATUS_ERROR_BAD_CONNECTION_PARAMS);
    assert_non_null(strstr(error, "contains no cipher names"));
}

static void test_unrecognized_cipher_name(void **unused) {
    sf_tls_policy_result policy;
    char error[512];
    (void) unused;
    assert_int_equal(sf_tls_policy_from_values("DHE-RSA-AES256-GCM-SHA384", NULL,
                                              &policy, error, sizeof(error)),
                     SF_STATUS_ERROR_BAD_CONNECTION_PARAMS);
    assert_non_null(strstr(error, "SNOWFLAKE_TLS_CIPHERS does not recognize 'DHE-RSA-AES256-GCM-SHA384'"));
}

static void test_connect_rejects_unrecognized_cipher(void **unused) {
    (void) unused;
    sf_setenv(SNOWFLAKE_TLS_CIPHERS_ENV, "DHE-RSA-AES256-GCM-SHA384");
    assert_connect_rejects("SNOWFLAKE_TLS_CIPHERS does not recognize 'DHE-RSA-AES256-GCM-SHA384'");
}

static void test_tls13_list_restricts_only_tls13(void **unused) {
    sf_tls_policy_result policy;
    char error[512];
    (void) unused;
    assert_int_equal(sf_tls_policy_from_values(
                         " TLS_AES_128_GCM_SHA256 : TLS_AES_256_GCM_SHA384 ",
                         NULL, &policy, error, sizeof(error)),
                     SF_STATUS_SUCCESS);
    assert_int_equal(policy.tls13.restricted, 1);
    assert_string_equal(policy.tls13.list, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    assert_int_equal(policy.tls12.restricted, 0);
}

static void test_connect_rejects_invalid_min_version(void **unused) {
    (void) unused;
    sf_setenv(SNOWFLAKE_MIN_TLS_VERSION_ENV, "tls1.1");
    assert_connect_rejects("invalid SNOWFLAKE_MIN_TLS_VERSION value: tls1.1");
}

static void test_min_version_1_3(void **unused) {
    sf_tls_policy_result policy;
    char error[512];
    (void) unused;
    assert_int_equal(sf_tls_policy_from_values(NULL, "1.3", &policy, error, sizeof(error)),
                     SF_STATUS_SUCCESS);
    assert_int_equal(policy.min_version, CURL_SSLVERSION_TLSv1_3);
}

typedef struct tls_version_capture {
    int called;
    int max_proto;
} tls_version_capture;

static CURLcode capture_max_proto(CURL *curl, void *sslctx, void *user) {
    tls_version_capture *capture = (tls_version_capture *) user;
    (void) curl;
    capture->called = 1;
    capture->max_proto = SSL_CTX_get_max_proto_version((SSL_CTX *) sslctx);
    return CURLE_ABORTED_BY_CALLBACK;
}

static int listen_loopback(tls_socket_t *listener, int *port) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int reuse = 1;
    *listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (TLS_SOCKET_BAD(*listener)) {
        return -1;
    }
#ifdef _WIN32
    setsockopt(*listener, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));
#else
    setsockopt(*listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(*listener, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(*listener, 1) != 0 ||
        getsockname(*listener, (struct sockaddr *) &addr, &addr_len) != 0) {
        close_tls_socket(*listener);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return 0;
}

/*
 * setTlsVersion(TLS 1.2 max) must survive policy application when
 * SNOWFLAKE_MIN_TLS_VERSION is unset. Reading the OpenSSL context avoids
 * depending on which version the peer prefers to negotiate.
 */
static void test_apply_keeps_tls12_maximum(void **unused) {
    tls_socket_t listener;
    int port = 0;
    int listened;
    int applied;
    CURL *curl = NULL;
    char url[64];
    tls_version_capture capture;
    long capped_tls12 = (long) CURL_SSLVERSION_TLSv1_2 | (long) CURL_SSLVERSION_MAX_TLSv1_2;
    (void) unused;
    memset(&capture, 0, sizeof(capture));
    assert_int_equal(sf_curl_apply_tls_policy_with_version(NULL, capped_tls12), -1);
    listened = listen_loopback(&listener, &port);
    if (listened == 0) {
        curl = curl_easy_init();
    }
    if (curl != NULL) {
        snprintf(url, sizeof(url), "https://127.0.0.1:%d/", port);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, capture_max_proto);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &capture);
        applied = sf_curl_apply_tls_policy_with_version(curl, capped_tls12);
        if (applied == 0) {
            (void) curl_easy_perform(curl);
        }
        curl_easy_cleanup(curl);
    } else {
        applied = -1;
    }
    if (listened == 0) {
        close_tls_socket(listener);
    }
    assert_int_equal(listened, 0);
    assert_non_null(curl);
    assert_int_equal(applied, 0);
    assert_true(capture.called);
    assert_int_equal(capture.max_proto, TLS1_2_VERSION);
}

static void test_effective_version_is_a_floor(void **unused) {
    long capped_tls12 = (long) CURL_SSLVERSION_TLSv1_2 | ((long) CURL_SSLVERSION_TLSv1_2 << 16);
    (void) unused;
    assert_int_equal(sf_tls_effective_ssl_version(CURL_SSLVERSION_TLSv1_2, CURL_SSLVERSION_TLSv1_3),
                     CURL_SSLVERSION_TLSv1_3);
    assert_int_equal(sf_tls_effective_ssl_version(CURL_SSLVERSION_TLSv1_3, CURL_SSLVERSION_TLSv1_2),
                     CURL_SSLVERSION_TLSv1_3);
    assert_int_equal(sf_tls_effective_ssl_version(capped_tls12, CURL_SSLVERSION_TLSv1_3),
                     CURL_SSLVERSION_TLSv1_3);
    assert_int_equal(sf_tls_effective_ssl_version(capped_tls12, 0), capped_tls12);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_blank_cipher_list_is_unset, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_cipher_separators_only_fail, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_unrecognized_cipher_name, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_connect_rejects_unrecognized_cipher, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_tls13_list_restricts_only_tls13, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_connect_rejects_invalid_min_version, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_min_version_1_3, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_apply_keeps_tls12_maximum, setup_tls_env, teardown_tls_env),
        cmocka_unit_test_setup_teardown(test_effective_version_is_a_floor, setup_tls_env, teardown_tls_env),
    };
    int ret;
    initialize_test(SF_BOOLEAN_FALSE);
    ret = cmocka_run_group_tests(tests, NULL, NULL);
    snowflake_global_term();
    return ret;
}
