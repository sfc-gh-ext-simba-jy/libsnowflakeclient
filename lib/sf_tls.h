#ifndef SNOWFLAKE_SF_TLS_H
#define SNOWFLAKE_SF_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CURL_STATICLIB
#define CURL_STATICLIB
#endif
#include <curl/curl.h>
#include <snowflake/client.h>

/**
 * TLS revocation settings applied through CURLOPT_SSL_CTX_FUNCTION.
 * Must outlive every curl_easy_perform() on the handle it is set up for.
 */
struct sf_tls_config {
    SF_CRL_CONFIG crl;
};

/**
 * Installs (or clears, when no check is enabled) the SSL_CTX callback on the handle.
 */
CURLcode sf_tls_setup(CURL *curl, struct sf_tls_config *cfg);

void sf_tls_global_init(void);
void sf_tls_global_term(void);

#ifdef __cplusplus
}
#endif

#endif //SNOWFLAKE_SF_TLS_H
