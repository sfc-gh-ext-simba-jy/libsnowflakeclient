#ifndef SNOWFLAKE_TLS_POLICY_H
#define SNOWFLAKE_TLS_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <curl/curl.h>
#include <snowflake/client.h>

#define SNOWFLAKE_TLS_CIPHERS_ENV "SNOWFLAKE_TLS_CIPHERS"
#define SNOWFLAKE_MIN_TLS_VERSION_ENV "SNOWFLAKE_MIN_TLS_VERSION"

typedef struct sf_tls_cipher_selection {
    int restricted; /* non-zero when this generation is limited to list */
    char list[512];
} sf_tls_cipher_selection;

typedef struct sf_tls_policy_result {
    sf_tls_cipher_selection tls12;
    sf_tls_cipher_selection tls13;
    long min_version; /* 0 when unset; otherwise CURL_SSLVERSION_TLSv1_2 or _3 */
} sf_tls_policy_result;

/*
 * NULL cipher_value or min_version_value means that variable is unset.
 * Empty or whitespace-only cipher_value is treated as unset.
 * A cipher value that contains only separators (for example ": :") fails.
 */
SF_STATUS sf_tls_policy_from_values(const char *cipher_value,
                                    const char *min_version_value,
                                    sf_tls_policy_result *out,
                                    char *error,
                                    size_t error_len);

/* Reads both environment variables. Fails with SF_STATUS_ERROR_BAD_CONNECTION_PARAMS. */
SF_STATUS sf_tls_policy_check(char *error, size_t error_len);

/*
 * Floor against the current global SSL version. A higher minimum replaces
 * current_ssl_version entirely, so a CURL_SSLVERSION_MAX_* mask is not kept.
 * min_version 0 leaves current_ssl_version unchanged.
 */
long sf_tls_effective_ssl_version(long current_ssl_version, long min_version);

/*
 * Applies the process policy to one curl handle. Returns 0 on success.
 * Floors current_ssl_version with SNOWFLAKE_MIN_TLS_VERSION.
 * A CURL_SSLVERSION_MAX_* mask on current_ssl_version is kept when the
 * environment minimum does not raise the floor.
 * Sets CURLOPT_SSLVERSION always. Sets cipher options only for a generation
 * that SNOWFLAKE_TLS_CIPHERS restricts.
 */
int sf_curl_apply_tls_policy_with_version(CURL *curl, long current_ssl_version);

/*
 * sf_curl_apply_tls_policy_with_version(curl, SSL_VERSION).
 * cdecl on every platform: the AWS SDK stores this in a plain function pointer.
 */
int sf_curl_apply_tls_policy(CURL *curl);

#ifdef __cplusplus
}
#endif

#endif
