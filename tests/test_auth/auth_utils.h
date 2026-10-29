#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#include "../utils/test_setup.h"

void set_all_snowflake_attributes(SF_CONNECT *sf);

// Writes the `snowflake` token cache key component the driver uses for `sf`:
// the host, plus ":<port>" when the port was set explicitly.
void token_cache_snowflake_url(SF_CONNECT *sf, char *buf, size_t bufsize);

#endif
