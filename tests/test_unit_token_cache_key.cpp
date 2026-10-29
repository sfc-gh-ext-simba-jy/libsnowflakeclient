/*
 * File:   test_unit_token_cache_key.cpp
 *
 * Unit tests for the v2 token cache key: canonical-JSON serialization, the
 * cross-driver golden hash, URL/identifier normalization, dimension isolation
 * and input validation. These exercise only the key-derivation logic
 * (SecureStorage::convertTarget and the normalization helpers), so they run on
 * every platform regardless of the secure-storage backend.
 */

#include <string>

#include <boost/optional.hpp>

#include "snowflake/SecureStorage.hpp"

#include "utils/test_setup.h"

using namespace Snowflake::Client;

// Vector A — OAuth (DpopBundledAccessToken) golden key.
// Locked: changing this hash is a breaking change for cross-driver token sharing.
static const char* GOLDEN_KEY_OAUTH =
    "SnowflakeTokenCache.v2.DpopBundledAccessToken.741b6d66d252666d6821bfd19e0151511cf4efdaaeba2b3c87673aa4de6d2c0b";

// Vector B — MFA golden key.
// Locked: changing this hash is a breaking change for cross-driver token sharing.
static const char* GOLDEN_KEY_MFA =
    "SnowflakeTokenCache.v2.MfaToken.10c5dde84bb8f584c0df06ea826d418c4f580e08f9db10187c0cb5e2a732a0d6";

// Pre-normalized Vector A inputs (no scheme prefix — normalizeUrl is a no-op on
// already-stripped, already-lowercase strings). The quoted values are returned
// verbatim by normalizeIdentifier because they contain double-quote characters.
static SecureStorageKey golden_key_oauth()
{
  SecureStorageKey key;
  key.type = SecureStorageKeyType::DPOP_BUNDLED_ACCESS_TOKEN;
  key.idp       = "login.microsoftonline.com:443/tenant-id/oauth2/v2.0";
  key.snowflake = "myorg-myaccount.privatelink.snowflakecomputing.com";
  key.user      = "\"First Last\"@long-corporate-domain.example.com";
  key.role      = "\"Analyst Role With Spaces\":north_america:prod:readonly";
  return key;
}

void test_golden_hash(void **)
{
  auto result = SecureStorage::convertTarget(golden_key_oauth());
  assert_true(result.is_initialized());
  assert_string_equal(result.get().c_str(), GOLDEN_KEY_OAUTH);
}

void test_golden_hash_from_raw_inputs(void **)
{
  // Same key, but supplied with a scheme and mixed case; normalization must
  // reproduce the exact golden hash. Quoted segments use mixed case to verify
  // that normalizeIdentifier preserves them verbatim.
  SecureStorageKey key;
  key.type = SecureStorageKeyType::DPOP_BUNDLED_ACCESS_TOKEN;
  key.idp       = "https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0";
  key.snowflake = "https://myorg-myaccount.privatelink.snowflakecomputing.com";
  key.user      = "\"First Last\"@long-corporate-domain.example.com";
  key.role      = "\"Analyst Role With Spaces\":north_america:prod:readonly";

  auto result = SecureStorage::convertTarget(key);
  assert_true(result.is_initialized());
  assert_string_equal(result.get().c_str(), GOLDEN_KEY_OAUTH);
}

// Vector B — MFA golden hash (2-field keyData: snowflake + username only).
void test_golden_hash_mfa(void **)
{
  SecureStorageKey key;
  key.type      = SecureStorageKeyType::MFA_TOKEN;
  key.snowflake = "https://myorg-myaccount.privatelink.snowflakecomputing.com";
  key.user      = "\"First Last\"@long-corporate-domain.example.com";
  // idp and role are absent for MFA flows — not passed to convertTarget.

  auto result = SecureStorage::convertTarget(key);
  assert_true(result.is_initialized());
  assert_string_equal(result.get().c_str(), GOLDEN_KEY_MFA);
}

void test_key_has_versioned_prefix(void **)
{
  auto result = SecureStorage::convertTarget(golden_key_oauth());
  assert_true(result.is_initialized());
  // Key format: SnowflakeTokenCache.v2.<TokenType>.<hash>
  assert_true(result.get().rfind("SnowflakeTokenCache.v2.DpopBundledAccessToken.", 0) == 0);
}

void test_normalize_url(void **)
{
  assert_string_equal(
      normalizeUrl("https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0").c_str(),
      "login.microsoftonline.com:443/tenant-id/oauth2/v2.0");

  // Bare host: scheme stripped, no trailing slash.
  assert_string_equal(
      normalizeUrl("https://myorg-myaccount.privatelink.snowflakecomputing.com").c_str(),
      "myorg-myaccount.privatelink.snowflakecomputing.com");
  assert_string_equal(
      normalizeUrl("https://myorg-myaccount.snowflakecomputing.com/").c_str(),
      "myorg-myaccount.snowflakecomputing.com");

  // Non-root path is preserved (and lowercased).
  assert_string_equal(
      normalizeUrl("https://account.snowflakecomputing.com/path/to/resource").c_str(),
      "account.snowflakecomputing.com/path/to/resource");

  // Userinfo, query and fragment are dropped.
  assert_string_equal(
      normalizeUrl("https://user:pass@host.example.com/p?a=b#frag").c_str(),
      "host.example.com/p");

  // Userinfo is stripped from the authority only.
  assert_string_equal(
      normalizeUrl("https://user:pass@host.example.com/path").c_str(),
      "host.example.com/path");

  // An '@' after the authority is part of the path and must survive.
  assert_string_equal(
      normalizeUrl("https://host.example.com/oauth/@handle/token").c_str(),
      "host.example.com/oauth/@handle/token");

  // An '@' inside a dropped query string is never mistaken for userinfo.
  assert_string_equal(
      normalizeUrl("https://host.example.com/path?email=a@b.com").c_str(),
      "host.example.com/path");

  // Implicit default port is not added.
  assert_string_equal(
      normalizeUrl("https://host.example.com").c_str(),
      "host.example.com");

  // Userinfo is stripped from the authority and the path is lowercased.
  assert_string_equal(
      normalizeUrl("https://user:pass@host.example.com/Path").c_str(),
      "host.example.com/path");

  // An '@' in the path survives even when the authority has userinfo.
  assert_string_equal(
      normalizeUrl("https://user:pass@host.example.com/oauth/@handle/token").c_str(),
      "host.example.com/oauth/@handle/token");

  // Every trailing slash is removed, not only a slash on a bare host.
  assert_string_equal(
      normalizeUrl("https://idp.example.com/oauth/token/").c_str(),
      "idp.example.com/oauth/token");
  assert_string_equal(
      normalizeUrl("https://idp.example.com/oauth/token///").c_str(),
      "idp.example.com/oauth/token");

  // An explicit :443 stays when a trailing slash is also stripped.
  assert_string_equal(
      normalizeUrl("https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0/").c_str(),
      "login.microsoftonline.com:443/tenant-id/oauth2/v2.0");
}

void test_normalize_identifier(void **)
{
  // No quotes: entire value is lowercased.
  assert_string_equal(normalizeIdentifier("user@domain.com").c_str(), "user@domain.com");
  assert_string_equal(normalizeIdentifier("USER@DOMAIN.COM").c_str(), "user@domain.com");
  assert_string_equal(normalizeIdentifier("ANALYST_ROLE").c_str(), "analyst_role");

  // Contains a double-quote anywhere: returned verbatim, unchanged.
  assert_string_equal(
      normalizeIdentifier("\"First Last\"@long-corporate-domain.example.com").c_str(),
      "\"First Last\"@long-corporate-domain.example.com");
  assert_string_equal(
      normalizeIdentifier("\"Analyst Role With Spaces\":north_america:prod:readonly").c_str(),
      "\"Analyst Role With Spaces\":north_america:prod:readonly");

  // Quote not at position 0 — still triggers the verbatim path.
  assert_string_equal(
      normalizeIdentifier("prefix-\"seg\"").c_str(),
      "prefix-\"seg\"");
}

static std::string keyString(const std::string& idp, const std::string& snowflake,
                             const std::string& user, const std::string& role,
                             SecureStorageKeyType type)
{
  SecureStorageKey key;
  key.type = type;
  key.idp = idp;
  key.snowflake = snowflake;
  key.user = user;
  key.role = role;
  auto result = SecureStorage::convertTarget(key);
  assert_true(result.is_initialized());
  return result.get();
}

void test_different_snowflake_hosts_differ(void **)
{
  std::string a = keyString("IDP.EXAMPLE.COM", "ACCOUNT1.SNOWFLAKECOMPUTING.COM", "USER", "",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string b = keyString("IDP.EXAMPLE.COM", "ACCOUNT2.SNOWFLAKECOMPUTING.COM", "USER", "",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_true(a != b);
}

void test_same_idp_different_snowflake_differ(void **)
{
  std::string a = keyString("IDP.SHARED.COM", "ORG-ACCOUNT1.SNOWFLAKECOMPUTING.COM", "USER", "",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string b = keyString("IDP.SHARED.COM", "ORG-ACCOUNT2.SNOWFLAKECOMPUTING.COM", "USER", "",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_true(a != b);
}

void test_different_roles_differ(void **)
{
  std::string a = keyString("IDP.EXAMPLE.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "ROLE_A",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string b = keyString("IDP.EXAMPLE.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "ROLE_B",
                            SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_true(a != b);
}

void test_different_token_types_differ(void **)
{
  std::string a = keyString("HOST.EXAMPLE.COM", "HOST.EXAMPLE.COM", "USER", "",
                            SecureStorageKeyType::ID_TOKEN);
  std::string b = keyString("HOST.EXAMPLE.COM", "HOST.EXAMPLE.COM", "USER", "",
                            SecureStorageKeyType::MFA_TOKEN);
  assert_true(a != b);
}

void test_mfa_oauth_same_host_user_differ(void **)
{
  // MFA and OAuth keys for the same host/user must differ: they differ by
  // the token type in the prefix AND by field set (2 vs 4 fields).
  std::string mfa = keyString("IDP.EXAMPLE.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "",
                              SecureStorageKeyType::MFA_TOKEN);
  std::string oauth = keyString("IDP.EXAMPLE.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "",
                                SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_true(mfa != oauth);
}

void test_mfa_empty_role_is_stable(void **)
{
  std::string a = keyString("ACCOUNT.SNOWFLAKECOMPUTING.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM",
                            "USER", "", SecureStorageKeyType::MFA_TOKEN);
  std::string b = keyString("ACCOUNT.SNOWFLAKECOMPUTING.COM", "ACCOUNT.SNOWFLAKECOMPUTING.COM",
                            "USER", "", SecureStorageKeyType::MFA_TOKEN);
  assert_true(a == b);
  assert_true(a.rfind("SnowflakeTokenCache.v2.", 0) == 0);
}

void test_backward_compatible_ctor_sets_idp_snowflake(void **)
{
  // The (host, user, type) constructor maps to idp == snowflake == host.
  // For MFA flows idp is excluded from the key, so both constructors must
  // produce the same result.
  SecureStorageKey compat("host.example.com", "user", SecureStorageKeyType::MFA_TOKEN);
  std::string viaCompat = SecureStorage::convertTarget(compat).get();
  std::string explicitKey = keyString("host.example.com", "host.example.com", "user", "",
                                      SecureStorageKeyType::MFA_TOKEN);
  assert_string_equal(viaCompat.c_str(), explicitKey.c_str());
}

void test_validation_rejects_empty_snowflake(void **)
{
  SecureStorageKey key;
  key.type = SecureStorageKeyType::ID_TOKEN;
  key.idp = "";
  key.snowflake = "";
  key.user = "user";
  assert_false(SecureStorage::convertTarget(key).is_initialized());
}

void test_validation_rejects_empty_user(void **)
{
  SecureStorageKey key;
  key.type = SecureStorageKeyType::ID_TOKEN;
  key.idp = "host.example.com";
  key.snowflake = "host.example.com";
  key.user = "";
  assert_false(SecureStorage::convertTarget(key).is_initialized());
}

void test_mfa_id_does_not_require_idp(void **)
{
  // For MFA and ID-token flows, idp is excluded from keyData.
  // An empty idp must not cause convertTarget to fail.
  SecureStorageKey key;
  key.type      = SecureStorageKeyType::ID_TOKEN;
  key.idp       = "";   // deliberately empty — not used for this flow
  key.snowflake = "host.example.com";
  key.user      = "user";
  assert_true(SecureStorage::convertTarget(key).is_initialized());
}

void test_validation_rejects_empty_idp_for_oauth(void **)
{
  SecureStorageKey key;
  key.type = SecureStorageKeyType::OAUTH_ACCESS_TOKEN;
  key.idp = "";
  key.snowflake = "host.example.com";
  key.user = "user";
  key.role = "";
  assert_false(SecureStorage::convertTarget(key).is_initialized());

  // A scheme-only URL normalizes to empty and is rejected the same way.
  key.idp = "https://";
  assert_false(SecureStorage::convertTarget(key).is_initialized());

  key.type = SecureStorageKeyType::OAUTH_REFRESH_TOKEN;
  key.idp = "";
  assert_false(SecureStorage::convertTarget(key).is_initialized());

  key.type = SecureStorageKeyType::DPOP_BUNDLED_ACCESS_TOKEN;
  assert_false(SecureStorage::convertTarget(key).is_initialized());
}

void test_oauth_allows_empty_role(void **)
{
  SecureStorageKey key;
  key.type = SecureStorageKeyType::OAUTH_REFRESH_TOKEN;
  key.idp = "https://idp.example.com/oauth/token";
  key.snowflake = "https://account.snowflakecomputing.com";
  key.user = "USER";
  key.role = "";
  auto result = SecureStorage::convertTarget(key);
  assert_true(result.is_initialized());
  assert_true(result.get().rfind("SnowflakeTokenCache.v2.OauthRefreshToken.", 0) == 0);
}

void test_mfa_ignores_idp_and_role(void **)
{
  // MFA keyData is snowflake + username only. A populated idp or role must
  // not change the key.
  std::string without = keyString("", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "",
                                  SecureStorageKeyType::MFA_TOKEN);
  std::string with = keyString("https://idp.example.com/oauth/token",
                               "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "ANALYST",
                               SecureStorageKeyType::MFA_TOKEN);
  assert_string_equal(without.c_str(), with.c_str());
  assert_true(without.rfind("SnowflakeTokenCache.v2.MfaToken.", 0) == 0);

  std::string idWithout = keyString("", "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "",
                                    SecureStorageKeyType::ID_TOKEN);
  std::string idWith = keyString("https://idp.example.com/oauth/token",
                                 "ACCOUNT.SNOWFLAKECOMPUTING.COM", "USER", "ANALYST",
                                 SecureStorageKeyType::ID_TOKEN);
  assert_string_equal(idWithout.c_str(), idWith.c_str());
  assert_true(idWithout.rfind("SnowflakeTokenCache.v2.IdToken.", 0) == 0);
}

void test_oauth_types_share_keydata_hash(void **)
{
  // token_type is the prefix only. The three OAuth types share keyData, so
  // they share a digest and differ by the PascalCase segment.
  std::string access = keyString("IDP.EXAMPLE.COM/oauth/token", "ACCOUNT.SNOWFLAKECOMPUTING.COM",
                                 "USER", "ROLE", SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string refresh = keyString("IDP.EXAMPLE.COM/oauth/token", "ACCOUNT.SNOWFLAKECOMPUTING.COM",
                                  "USER", "ROLE", SecureStorageKeyType::OAUTH_REFRESH_TOKEN);
  std::string dpop = keyString("IDP.EXAMPLE.COM/oauth/token", "ACCOUNT.SNOWFLAKECOMPUTING.COM",
                               "USER", "ROLE", SecureStorageKeyType::DPOP_BUNDLED_ACCESS_TOKEN);
  assert_true(access.rfind("SnowflakeTokenCache.v2.OauthAccessToken.", 0) == 0);
  assert_true(refresh.rfind("SnowflakeTokenCache.v2.OauthRefreshToken.", 0) == 0);
  assert_true(dpop.rfind("SnowflakeTokenCache.v2.DpopBundledAccessToken.", 0) == 0);
  assert_true(access != refresh);
  assert_true(access != dpop);

  std::string accessHash = access.substr(access.rfind('.') + 1);
  std::string refreshHash = refresh.substr(refresh.rfind('.') + 1);
  std::string dpopHash = dpop.substr(dpop.rfind('.') + 1);
  assert_string_equal(accessHash.c_str(), refreshHash.c_str());
  assert_string_equal(accessHash.c_str(), dpopHash.c_str());
  assert_int_equal(accessHash.size(), 64);
}

void test_unquoted_case_folds_to_same_key(void **)
{
  std::string mixed = keyString("HTTPS://IDP.EXAMPLE.COM/OAuth/Token/",
                                "HTTPS://Account.SnowflakeComputing.com/",
                                "USER@DOMAIN.COM", "ANALYST",
                                SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string folded = keyString("idp.example.com/oauth/token",
                                 "account.snowflakecomputing.com",
                                 "user@domain.com", "analyst",
                                 SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_string_equal(mixed.c_str(), folded.c_str());
}

void test_snowflake_port_isolates_key(void **)
{
  std::string bare = keyString("", "account.snowflakecomputing.com", "user", "",
                               SecureStorageKeyType::MFA_TOKEN);
  std::string port8443 = keyString("", "account.snowflakecomputing.com:8443", "user", "",
                                   SecureStorageKeyType::MFA_TOKEN);
  std::string port443 = keyString("", "account.snowflakecomputing.com:443", "user", "",
                                  SecureStorageKeyType::MFA_TOKEN);
  assert_true(bare != port8443);
  assert_true(bare != port443);
  assert_true(port443 != port8443);

  std::string oauthBare = keyString("idp.example.com/oauth/token", "account.snowflakecomputing.com",
                                    "user", "", SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  std::string oauthPort = keyString("idp.example.com/oauth/token", "account.snowflakecomputing.com:8443",
                                    "user", "", SecureStorageKeyType::OAUTH_ACCESS_TOKEN);
  assert_true(oauthBare != oauthPort);
}

void test_validation_rejects_unknown_token_type(void **)
{
  SecureStorageKey key;
  key.type = static_cast<SecureStorageKeyType>(99);
  key.snowflake = "account.snowflakecomputing.com";
  key.user = "user";
  assert_false(SecureStorage::convertTarget(key).is_initialized());
}

// TODO(SNOW-4343744): pins the ASCII-only lowercasing; the Rust reference
// lowercases non-ASCII letters too ("ÜSER" -> "üser").
void test_non_ascii_is_not_lowercased(void **)
{
  assert_string_equal(normalizeIdentifier("\xC3\x9CSER").c_str(), "\xC3\x9Cser");
  assert_string_equal(normalizeUrl("https://\xC3\x9C" "BER.EXAMPLE.COM").c_str(), "\xC3\x9C" "ber.example.com");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_golden_hash),
      cmocka_unit_test(test_golden_hash_from_raw_inputs),
      cmocka_unit_test(test_golden_hash_mfa),
      cmocka_unit_test(test_key_has_versioned_prefix),
      cmocka_unit_test(test_normalize_url),
      cmocka_unit_test(test_normalize_identifier),
      cmocka_unit_test(test_different_snowflake_hosts_differ),
      cmocka_unit_test(test_same_idp_different_snowflake_differ),
      cmocka_unit_test(test_different_roles_differ),
      cmocka_unit_test(test_different_token_types_differ),
      cmocka_unit_test(test_mfa_oauth_same_host_user_differ),
      cmocka_unit_test(test_mfa_empty_role_is_stable),
      cmocka_unit_test(test_backward_compatible_ctor_sets_idp_snowflake),
      cmocka_unit_test(test_validation_rejects_empty_snowflake),
      cmocka_unit_test(test_validation_rejects_empty_user),
      cmocka_unit_test(test_mfa_id_does_not_require_idp),
      cmocka_unit_test(test_validation_rejects_empty_idp_for_oauth),
      cmocka_unit_test(test_oauth_allows_empty_role),
      cmocka_unit_test(test_mfa_ignores_idp_and_role),
      cmocka_unit_test(test_oauth_types_share_keydata_hash),
      cmocka_unit_test(test_unquoted_case_folds_to_same_key),
      cmocka_unit_test(test_snowflake_port_isolates_key),
      cmocka_unit_test(test_validation_rejects_unknown_token_type),
      cmocka_unit_test(test_non_ascii_is_not_lowercased),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
