#include <stdbool.h>
#include <openssl/ssl.h>
#include <snowflake/logger.h>
#include "snowflake/platform.h"
#include "sf_tls.h"

/* Implemented in the patched libcurl (patches/curl/lib/vtls/sf_crl.c). */
void STDCALL registerCRLCheck(X509_STORE *ctx,
                              bool crl_advisory,
                              bool crl_allow_no_crl,
                              bool crl_disk_caching,
                              bool crl_memory_caching,
                              long crl_download_timeout,
                              long crl_download_max_size);
void STDCALL setCertCRLLogger(void (*log_fn)(const char *msg));

static void crl_log(const char *msg) {
    log_debug("%s", msg);
}

/* Runs after curl has populated the SSL_CTX certificate store. */
static CURLcode sf_tls_ctx_cb(CURL *curl, void *ssl_ctx, void *userptr) {
    struct sf_tls_config *cfg = (struct sf_tls_config *) userptr;
    X509_STORE *store;
    (void) curl;

    if (cfg->crl.check) {
        store = SSL_CTX_get_cert_store((SSL_CTX *) ssl_ctx);
        if (!store) {
            log_error("CRL check is enabled but SSL_CTX has no certificate store");
            return CURLE_SSL_CERTPROBLEM;
        }
        registerCRLCheck(store,
                         cfg->crl.advisory,
                         cfg->crl.allow_no_crl,
                         cfg->crl.disk_caching,
                         cfg->crl.memory_caching,
                         cfg->crl.download_timeout > 0 ? cfg->crl.download_timeout
                                                       : SF_CRL_DOWNLOAD_TIMEOUT,
                         cfg->crl.download_max_size > 0 ? cfg->crl.download_max_size : 0);
    }
    return CURLE_OK;
}

CURLcode sf_tls_setup(CURL *curl, struct sf_tls_config *cfg) {
    sf_bool enabled = cfg && cfg->crl.check;
    curl_ssl_ctx_callback cb = enabled ? sf_tls_ctx_cb : NULL;
    CURLcode res;

    res = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, cb);
    if (res != CURLE_OK) {
        return res;
    }
    return curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, enabled ? (void *) cfg : NULL);
}

void sf_tls_global_init(void) {
    setCertCRLLogger(crl_log);
}

void sf_tls_global_term(void) {
    setCertCRLLogger(NULL);
}
