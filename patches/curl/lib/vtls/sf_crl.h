#ifndef HEADER_CURL_SF_CRL_H
#define HEADER_CURL_SF_CRL_H

#include <stdbool.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#define SF_PUBLIC(type)   __declspec(dllexport) type __stdcall
#else
#define SF_PUBLIC(type) type
#endif

#define SF_CRL_DOWNLOAD_MAX_SIZE (20 * 1024 * 1024) /* 20 MB */

#define SF_CRL_RESPONSE_CACHE_DIR_ENV "SF_CRL_RESPONSE_CACHE_DIR"
#define SF_CRL_CACHE_VALIDITY_TIME_ENV "SF_CRL_CACHE_VALIDITY_TIME"
#define SF_CRL_ON_DISK_CACHE_REMOVAL_DELAY_ENV "SF_CRL_ON_DISK_CACHE_REMOVAL_DELAY"
#define SF_CRL_CACHE_CLEANUP_INTERVAL_ENV "SF_CRL_CACHE_CLEANUP_INTERVAL"

#define SF_CRL_CACHE_VALIDITY_TIME_DEFAULT 86400L          /* 24 hours */
#define SF_CRL_ON_DISK_CACHE_REMOVAL_DELAY_DEFAULT 604800L /* 7 days */
#define SF_CRL_CACHE_CLEANUP_INTERVAL_DEFAULT 3600L        /* 1 hour */

typedef void (*sf_crl_log_fn)(const char *msg);

SF_PUBLIC(void) registerCRLCheck(X509_STORE *ctx,
                                 bool crl_advisory,
                                 bool crl_allow_no_crl,
                                 bool crl_disk_caching,
                                 bool crl_memory_caching,
                                 long crl_download_timeout,
                                 long crl_download_max_size);

SF_PUBLIC(void) initCertCRL(void);
SF_PUBLIC(void) termCertCRL(void);
SF_PUBLIC(void) setCertCRLLogger(sf_crl_log_fn log_fn);

/* Remove expired/evicted in-memory CRLs and old on-disk cache files. */
SF_PUBLIC(void) cleanupCertCRLCache(void);

#endif
