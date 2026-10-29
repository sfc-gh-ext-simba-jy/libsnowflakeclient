#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <snowflake/logger.h>
#include <snowflake/tls_policy.h>
#include "constants.h"

static const char *const TLS13_SUITES[] = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    NULL
};

static const char *const TLS12_SUITES[] = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    NULL
};

static const char NO_CIPHER_NAMES[] =
    "SNOWFLAKE_TLS_CIPHERS contains no cipher names. "
    "Expected a colon-separated list, for example "
    "'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384'.";

static SF_STATUS set_policy_error(char *error, size_t error_len, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (error != NULL && error_len > 0) {
        vsnprintf(error, error_len, fmt, ap);
    }
    va_end(ap);
    return SF_STATUS_ERROR_BAD_CONNECTION_PARAMS;
}

static int is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int is_blank(const char *value) {
    if (value == NULL) {
        return 1;
    }
    while (*value != '\0') {
        if (!is_space((unsigned char) *value)) {
            return 0;
        }
        value++;
    }
    return 1;
}

static int name_in_list(const char *const *list, const char *name) {
    size_t i;
    for (i = 0; list[i] != NULL; i++) {
        if (strcmp(list[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int list_contains(const char *list, const char *name) {
    size_t name_len = strlen(name);
    const char *cursor = list;
    while ((cursor = strstr(cursor, name)) != NULL) {
        int at_start = (cursor == list) || (cursor[-1] == ':');
        int at_end = (cursor[name_len] == '\0') || (cursor[name_len] == ':');
        if (at_start && at_end) {
            return 1;
        }
        cursor += name_len;
    }
    return 0;
}

static int suite_offered(const char *name, int tls13) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    int offered = 0;
    if (ctx == NULL) {
        return 0;
    }
    if (tls13) {
        offered = SSL_CTX_set_ciphersuites(ctx, name) == 1;
    } else {
        offered = SSL_CTX_set_cipher_list(ctx, name) == 1;
    }
    SSL_CTX_free(ctx);
    return offered;
}

static int default_tls12_offered(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    int offered = 0;
    if (ctx == NULL) {
        return 0;
    }
    offered = SSL_CTX_set_cipher_list(ctx, "DEFAULT") == 1;
    SSL_CTX_free(ctx);
    return offered;
}

static int default_tls13_offered(void) {
    return suite_offered("TLS_AES_128_GCM_SHA256", 1)
        || suite_offered("TLS_AES_256_GCM_SHA384", 1)
        || suite_offered("TLS_CHACHA20_POLY1305_SHA256", 1);
}

static int version_rank(long version) {
    switch (version & 0xFFFFL) {
        case CURL_SSLVERSION_TLSv1_3:
            return 3;
        case CURL_SSLVERSION_TLSv1_2:
            return 2;
        default:
            return 1;
    }
}

long sf_tls_effective_ssl_version(long current_ssl_version, long min_version) {
    if (min_version == 0) {
        return current_ssl_version;
    }
    if (version_rank(min_version) > version_rank(current_ssl_version)) {
        return min_version;
    }
    return current_ssl_version;
}

static int tls12_enabled(long effective) {
    return (effective & 0xFFFFL) != CURL_SSLVERSION_TLSv1_3;
}

static SF_STATUS append_suite(sf_tls_cipher_selection *selection, const char *name,
                              char *error, size_t error_len) {
    size_t current_len;
    size_t name_len;
    if (list_contains(selection->list, name)) {
        return SF_STATUS_SUCCESS;
    }
    current_len = strlen(selection->list);
    name_len = strlen(name);
    if (current_len + (current_len > 0 ? 1 : 0) + name_len + 1 > sizeof(selection->list)) {
        return set_policy_error(error, error_len, "SNOWFLAKE_TLS_CIPHERS is too long");
    }
    if (current_len > 0) {
        selection->list[current_len++] = ':';
    }
    memcpy(selection->list + current_len, name, name_len + 1);
    selection->restricted = 1;
    return SF_STATUS_SUCCESS;
}

static SF_STATUS add_named_suite(sf_tls_policy_result *out, const char *name,
                                 char *error, size_t error_len) {
    int tls13 = strncmp(name, "TLS_", 4) == 0;
    const char *const *known = tls13 ? TLS13_SUITES : TLS12_SUITES;
    sf_tls_cipher_selection *selection = tls13 ? &out->tls13 : &out->tls12;
    if (!name_in_list(known, name)) {
        return set_policy_error(error, error_len,
                                "SNOWFLAKE_TLS_CIPHERS does not recognize '%s'", name);
    }
    if (!suite_offered(name, tls13)) {
        return set_policy_error(error, error_len,
                                "SNOWFLAKE_TLS_CIPHERS requests '%s', which this build does not offer",
                                name);
    }
    return append_suite(selection, name, error, error_len);
}

static SF_STATUS parse_min_version(const char *value, long *min_version,
                                   char *error, size_t error_len) {
    char normalized[64];
    size_t length;
    size_t i;
    if (value == NULL) {
        *min_version = 0;
        return SF_STATUS_SUCCESS;
    }
    while (is_space((unsigned char) *value)) {
        value++;
    }
    length = strlen(value);
    while (length > 0 && is_space((unsigned char) value[length - 1])) {
        length--;
    }
    if (length == 0) {
        *min_version = 0;
        return SF_STATUS_SUCCESS;
    }
    if (length >= sizeof(normalized)) {
        return set_policy_error(error, error_len,
                                "invalid SNOWFLAKE_MIN_TLS_VERSION value: %.32s. "
                                "Valid values are: 1.2, 1.3, TLSv1.2, TLSv1.3",
                                value);
    }
    for (i = 0; i < length; i++) {
        normalized[i] = (char) tolower((unsigned char) value[i]);
    }
    normalized[length] = '\0';
    if (strcmp(normalized, "1.2") == 0 || strcmp(normalized, "tlsv1.2") == 0) {
        *min_version = CURL_SSLVERSION_TLSv1_2;
        return SF_STATUS_SUCCESS;
    }
    if (strcmp(normalized, "1.3") == 0 || strcmp(normalized, "tlsv1.3") == 0) {
        *min_version = CURL_SSLVERSION_TLSv1_3;
        return SF_STATUS_SUCCESS;
    }
    return set_policy_error(error, error_len,
                            "invalid SNOWFLAKE_MIN_TLS_VERSION value: %s. "
                            "Valid values are: 1.2, 1.3, TLSv1.2, TLSv1.3",
                            normalized);
}

static SF_STATUS parse_ciphers(const char *value, sf_tls_policy_result *out,
                               char *error, size_t error_len) {
    char raw[4096];
    char *cursor;
    int saw_name = 0;
    size_t length;
    if (value == NULL || is_blank(value)) {
        return SF_STATUS_SUCCESS;
    }
    length = strlen(value);
    if (length >= sizeof(raw)) {
        return set_policy_error(error, error_len, "SNOWFLAKE_TLS_CIPHERS is too long");
    }
    memcpy(raw, value, length + 1);
    cursor = raw;
    for (;;) {
        char *colon = strchr(cursor, ':');
        char *start;
        char *end;
        if (colon != NULL) {
            *colon = '\0';
        }
        start = cursor;
        while (is_space((unsigned char) *start)) {
            start++;
        }
        end = start + strlen(start);
        while (end > start && is_space((unsigned char) end[-1])) {
            end--;
        }
        if (end > start) {
            SF_STATUS status;
            *end = '\0';
            saw_name = 1;
            status = add_named_suite(out, start, error, error_len);
            if (status != SF_STATUS_SUCCESS) {
                return status;
            }
        }
        if (colon == NULL) {
            break;
        }
        cursor = colon + 1;
    }
    if (!saw_name) {
        return set_policy_error(error, error_len, "%s", NO_CIPHER_NAMES);
    }
    return SF_STATUS_SUCCESS;
}

static int generation_has_suite(const sf_tls_cipher_selection *selection, int tls13) {
    if (selection->restricted) {
        return selection->list[0] != '\0';
    }
    return tls13 ? default_tls13_offered() : default_tls12_offered();
}

SF_STATUS sf_tls_policy_from_values(const char *cipher_value,
                                    const char *min_version_value,
                                    sf_tls_policy_result *out,
                                    char *error,
                                    size_t error_len) {
    SF_STATUS status;
    long effective;
    if (out == NULL) {
        return set_policy_error(error, error_len, "TLS policy output is missing");
    }
    memset(out, 0, sizeof(*out));
    if (error != NULL && error_len > 0) {
        error[0] = '\0';
    }
    status = parse_min_version(min_version_value, &out->min_version, error, error_len);
    if (status != SF_STATUS_SUCCESS) {
        return status;
    }
    status = parse_ciphers(cipher_value, out, error, error_len);
    if (status != SF_STATUS_SUCCESS) {
        return status;
    }
    effective = sf_tls_effective_ssl_version((long) SSL_VERSION, out->min_version);
    if (tls12_enabled(effective) && !generation_has_suite(&out->tls12, 0)) {
        return set_policy_error(error, error_len,
                                "SNOWFLAKE_TLS_CIPHERS leaves TLS 1.2 with no cipher suite");
    }
    if (!generation_has_suite(&out->tls13, 1)) {
        return set_policy_error(error, error_len,
                                "SNOWFLAKE_TLS_CIPHERS leaves TLS 1.3 with no cipher suite");
    }
    return SF_STATUS_SUCCESS;
}

SF_STATUS sf_tls_policy_check(char *error, size_t error_len) {
    sf_tls_policy_result policy;
    return sf_tls_policy_from_values(getenv(SNOWFLAKE_TLS_CIPHERS_ENV),
                                     getenv(SNOWFLAKE_MIN_TLS_VERSION_ENV),
                                     &policy, error, error_len);
}

int sf_curl_apply_tls_policy_with_version(CURL *curl, long current_ssl_version) {
    char error[512];
    sf_tls_policy_result policy;
    long effective;
    if (curl == NULL) {
        return -1;
    }
    if (sf_tls_policy_from_values(getenv(SNOWFLAKE_TLS_CIPHERS_ENV),
                                  getenv(SNOWFLAKE_MIN_TLS_VERSION_ENV),
                                  &policy, error, sizeof(error)) != SF_STATUS_SUCCESS) {
        log_error("%s", error);
        return -1;
    }
    effective = sf_tls_effective_ssl_version(current_ssl_version, policy.min_version);
    if (curl_easy_setopt(curl, CURLOPT_SSLVERSION, effective) != CURLE_OK) {
        log_error("Failed to set CURLOPT_SSLVERSION");
        return -1;
    }
    if (policy.tls13.restricted &&
        curl_easy_setopt(curl, CURLOPT_TLS13_CIPHERS, policy.tls13.list) != CURLE_OK) {
        log_error("Failed to set CURLOPT_TLS13_CIPHERS");
        return -1;
    }
    if (policy.tls12.restricted &&
        curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, policy.tls12.list) != CURLE_OK) {
        log_error("Failed to set CURLOPT_SSL_CIPHER_LIST");
        return -1;
    }
    return 0;
}

int sf_curl_apply_tls_policy(CURL *curl) {
    return sf_curl_apply_tls_policy_with_version(curl, (long) SSL_VERSION);
}
