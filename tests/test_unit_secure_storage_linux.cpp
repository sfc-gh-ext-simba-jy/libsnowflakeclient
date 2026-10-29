/*
 * File:   test_unit_secure_storage.cpp
 */

#include <iostream>
#include <fstream>
#include <iterator>

#include <sys/stat.h>
#include <unistd.h>

#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include "snowflake/FileLock.hpp"
#include "snowflake/SecureStorage.hpp"
#include "linux/CacheFile.hpp"

#include "utils/test_setup.h"
#include "utils/EnvOverride.hpp"

constexpr const char* CACHE_FILENAME = "credential_cache_v2.json";

using namespace Snowflake::Client;

void remove_file_if_exists(const std::string& path)
{
  boost::system::error_code ec;
  boost::filesystem::remove_all(path, ec);
  assert_true(!ec);
}

void assert_permissions(const std::string& path, boost::filesystem::perms permissions)
{
  boost::filesystem::file_status s = boost::filesystem::status( path );
  assert_true((s.permissions() & boost::filesystem::perms_mask) == permissions);
}

std::string read_whole_file(const std::string& path)
{
  std::ifstream fs(path);
  return std::string((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
}

void write_whole_file(const std::string& path, const std::string& contents, mode_t mode)
{
  {
    std::ofstream fs(path, std::ios_base::trunc);
    assert_true(fs.is_open());
    fs << contents;
  }
  assert_int_equal(chmod(path.c_str(), mode), 0);
}

mode_t file_mode(const std::string& path)
{
  struct stat s = {};
  assert_int_equal(lstat(path.c_str(), &s), 0);
  return s.st_mode & 0777;
}

void test_secure_storage_simple(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);
  assert_permissions(std::string("sf_cache_dir/") + CACHE_FILENAME, boost::filesystem::owner_read | boost::filesystem::owner_write);
  assert_permissions("sf_cache_dir", boost::filesystem::owner_all);

  assert_true(ss.removeToken(key) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::NotFound);
}

void test_secure_storage_malformed_cache(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);
  assert_permissions(std::string("sf_cache_dir/") + CACHE_FILENAME, boost::filesystem::owner_read | boost::filesystem::owner_write);
  assert_permissions("sf_cache_dir", boost::filesystem::owner_all);

  {
    std::ofstream fs(std::string("sf_cache_dir/") + CACHE_FILENAME, std::ios_base::trunc);
    assert_true(fs.is_open());
    fs << "[]";
  }
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::NotFound);

  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);

  {
    std::ofstream fs(std::string("sf_cache_dir/") + CACHE_FILENAME, std::ios_base::trunc);
    assert_true(fs.is_open());
    fs << "{]";
  }
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::NotFound);

  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);

  {
    std::ofstream fs(std::string("sf_cache_dir/") + CACHE_FILENAME, std::ios_base::trunc);
    assert_true(fs.is_open());
    fs << "{ \"random field\": []}";
  }
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::NotFound);

  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);
}

void test_secure_storage_two_keys(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  SecureStorage ss;
  SecureStorageKey key1 { "host", "user1", SecureStorageKeyType::MFA_TOKEN };
  SecureStorageKey key2 { "host", "user2", SecureStorageKeyType::MFA_TOKEN };
  std::string token1 = "example_token";
  std::string token2 = "example_token";
  std::string retrievedToken;

  assert_true(ss.storeToken(key1, token1) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key1, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token1);
  assert_permissions(std::string("sf_cache_dir/") + CACHE_FILENAME, boost::filesystem::owner_read | boost::filesystem::owner_write);
  assert_permissions("sf_cache_dir", boost::filesystem::owner_all);

  assert_true(ss.storeToken(key2, token2) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key2, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token2);

  assert_true(ss.removeToken(key1) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key1, retrievedToken) == SecureStorageStatus::NotFound);
  assert_true(ss.retrieveToken(key2, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token2);

  assert_true(ss.removeToken(key2) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key1, retrievedToken) == SecureStorageStatus::NotFound);
  assert_true(ss.retrieveToken(key2, retrievedToken) == SecureStorageStatus::NotFound);
}

void test_secure_storage_home_dir(void **)
{
  boost::filesystem::remove_all("home");
  boost::filesystem::create_directory("home");
  EnvOverride override1("XDG_CACHE_HOME", boost::none);
  EnvOverride override2("HOME", "home");
  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);

  assert_true(boost::filesystem::exists(std::string("home/.cache/snowflake/") + CACHE_FILENAME));
  assert_permissions("home/.cache", boost::filesystem::owner_all);
  assert_permissions("home/.cache/snowflake", boost::filesystem::owner_all);
  assert_permissions(std::string("home/.cache/snowflake/") + CACHE_FILENAME, boost::filesystem::owner_read | boost::filesystem::owner_write);
}

void test_secure_storage_xdg_cache_home(void **)
{
  boost::filesystem::remove_all("cache_dir");
  boost::filesystem::create_directory("cache_dir");
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", boost::none);
  EnvOverride override2("XDG_CACHE_HOME", "cache_dir");
  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);

  assert_true(boost::filesystem::exists(std::string("cache_dir/snowflake/") + CACHE_FILENAME));
  assert_permissions("cache_dir/snowflake", boost::filesystem::owner_all);
  assert_permissions(std::string("cache_dir/snowflake/") + CACHE_FILENAME, boost::filesystem::owner_read | boost::filesystem::owner_write);
}

void test_secure_storage_update_key(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string newToken = "new_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(token == retrievedToken);
  assert_true(ss.storeToken(key, newToken) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(newToken == retrievedToken);
}

void test_file_lock_fails_while_held(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  std::string cachePath = std::string("sf_cache_dir/") + CACHE_FILENAME;

  FileLock holder(cachePath);
  assert_true(holder.isLocked());

  FileLock contender(cachePath, 3, std::chrono::milliseconds(1));
  assert_false(contender.isLocked());
}

void test_file_lock_released_and_lock_file_persists(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  std::string cachePath = std::string("sf_cache_dir/") + CACHE_FILENAME;
  std::string lockPath = cachePath + ".lck";

  {
    FileLock first(cachePath);
    assert_true(first.isLocked());
  }
  assert_true(boost::filesystem::is_regular_file(lockPath));
  assert_int_equal(file_mode(lockPath), 0600);

  FileLock second(cachePath, 1, std::chrono::milliseconds(1));
  assert_true(second.isLocked());
}

void test_secure_storage_leftover_lock_file_does_not_block(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  write_whole_file(std::string("sf_cache_dir/") + CACHE_FILENAME + ".lck", "", 0600);

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);
  assert_true(ss.removeToken(key) == SecureStorageStatus::Success);
}

void test_secure_storage_rejects_symlinked_cache_file(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  boost::filesystem::remove("symlink_target.json");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  const std::string targetContents = "{\"tokens\":{}}";
  write_whole_file("symlink_target.json", targetContents, 0600);
  std::string cachePath = std::string("sf_cache_dir/") + CACHE_FILENAME;
  assert_int_equal(symlink("../symlink_target.json", cachePath.c_str()), 0);

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  std::string retrievedToken;
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Error);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Error);
  assert_true(ss.removeToken(key) == SecureStorageStatus::Error);

  assert_string_equal(read_whole_file("symlink_target.json").c_str(), targetContents.c_str());
  boost::filesystem::remove("symlink_target.json");
}

void test_secure_storage_rejects_world_readable_cache_file_untouched(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  std::string cachePath = std::string("sf_cache_dir/") + CACHE_FILENAME;
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Success);
  const std::string original = read_whole_file(cachePath);
  assert_int_equal(chmod(cachePath.c_str(), 0644), 0);

  std::string retrievedToken;
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Error);
  assert_true(ss.storeToken(key, "other_token") == SecureStorageStatus::Error);
  assert_true(ss.removeToken(key) == SecureStorageStatus::Error);

  assert_string_equal(read_whole_file(cachePath).c_str(), original.c_str());
  assert_int_equal(file_mode(cachePath), 0644);
}

void test_secure_storage_invalid_cache_dir_env_does_not_fall_back(void **)
{
  boost::filesystem::remove_all("home");
  boost::filesystem::create_directory("home");
  write_whole_file("not_a_dir", "contents", 0600);
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "not_a_dir");
  EnvOverride override2("XDG_CACHE_HOME", boost::none);
  EnvOverride override3("HOME", "home");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  std::string retrievedToken;
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Error);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Error);
  assert_false(boost::filesystem::exists("home/.cache"));
  boost::filesystem::remove("not_a_dir");
}

void test_secure_storage_empty_env_falls_through(void **)
{
  boost::filesystem::remove_all("cache_dir");
  boost::filesystem::create_directory("cache_dir");
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "");
  EnvOverride override2("XDG_CACHE_HOME", "cache_dir");
  EnvOverride override3("SF_TEMPORARY_CREDENTIAL_CACHE_FILE_NAME", "");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Success);
  assert_true(boost::filesystem::exists(std::string("cache_dir/snowflake/") + CACHE_FILENAME));
}

void test_secure_storage_file_name_override(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  EnvOverride override2("SF_TEMPORARY_CREDENTIAL_CACHE_FILE_NAME", "custom_cache.json");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  std::string retrievedToken;
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(boost::filesystem::exists("sf_cache_dir/custom_cache.json"));
  assert_false(boost::filesystem::exists(std::string("sf_cache_dir/") + CACHE_FILENAME));
  assert_int_equal(file_mode("sf_cache_dir/custom_cache.json"), 0600);
}

void test_secure_storage_file_name_override_rejects_path(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  EnvOverride override2("SF_TEMPORARY_CREDENTIAL_CACHE_FILE_NAME", "../escape.json");

  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };
  assert_true(ss.storeToken(key, "example_token") == SecureStorageStatus::Error);
  assert_false(boost::filesystem::exists("escape.json"));
}

void test_secure_storage_fails_to_find_cache_path(void **)
{
  EnvOverride override1("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", boost::none);
  EnvOverride override2("XDG_CACHE_HOME", boost::none);
  EnvOverride override3("HOME", boost::none);
  SecureStorage ss;
  SecureStorageKey key { "host", "user", SecureStorageKeyType::MFA_TOKEN };

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Error);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Error);
  assert_true(ss.removeToken(key) == SecureStorageStatus::Error);
}

void test_secure_storage_c_api(void **)
{
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  SecureStorageKey key{"host", "user", SecureStorageKeyType::MFA_TOKEN};
  std::string token = "example_token";

  secure_storage_ptr ss = secure_storage_init();

  assert_true(secure_storage_save_credential(ss, key.host.c_str(), key.user.c_str(), key.type, token.c_str()));

  char* cred = secure_storage_get_credential(ss, key.host.c_str(), key.user.c_str(), key.type);
  assert_true(cred != nullptr);
  assert_true(strcmp(cred, "example_token") == 0);
  secure_storage_free_credential(cred);

  assert_true(secure_storage_remove_credential(ss, key.host.c_str(), key.user.c_str(), key.type));

  cred = secure_storage_get_credential(ss, key.host.c_str(), key.user.c_str(), key.type);
  assert_true(cred == nullptr);
  secure_storage_free_credential(cred);

  secure_storage_term(ss);
}

void test_secure_storage_file_key_is_final_v2_key(void **)
{
  // The Linux file backend must store the credential under the final
  // SnowflakeTokenCache.v2.<hash> key verbatim, with no extra hashing.
  boost::filesystem::remove_all("sf_cache_dir");
  mkdir("sf_cache_dir", 0700);
  EnvOverride override("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", "sf_cache_dir");
  SecureStorage ss;
  SecureStorageKey key{"account.snowflakecomputing.com", "user",
                       SecureStorageKeyType::OAUTH_ACCESS_TOKEN,
                       "idp.example.com", "account.snowflakecomputing.com", "analyst"};

  auto expectedKey = SecureStorage::convertTarget(key);
  assert_true(expectedKey.is_initialized());
  assert_true(expectedKey.get().rfind("SnowflakeTokenCache.v2.", 0) == 0);

  std::string token = "example_token";
  std::string retrievedToken;
  assert_true(ss.storeToken(key, token) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::Success);
  assert_true(retrievedToken == token);

  // The raw cache file must contain the final key verbatim.
  std::ifstream fs(std::string("sf_cache_dir/") + CACHE_FILENAME);
  std::string contents((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
  assert_true(contents.find(expectedKey.get()) != std::string::npos);

  assert_true(ss.removeToken(key) == SecureStorageStatus::Success);
  assert_true(ss.retrieveToken(key, retrievedToken) == SecureStorageStatus::NotFound);
}

void test_get_cache_dir_bad_path(void **)
{
  EnvOverride override("ENV_VAR", "fakepath");
  assert_false(getCacheDir("ENV_VAR", {}).is_initialized());
}

void test_get_cache_dir_not_a_dir(void **)
{
  EnvOverride override("ENV_VAR", "file");
  std::ofstream file("file", std::ios_base::trunc);
  assert_true(file.is_open());
  file << "contents";
  file.close();
  assert_false(getCacheDir("ENV_VAR", {}).is_initialized());
  boost::filesystem::remove("file");
}

int main(void) {
  /* Testing only file based credential cache, available on linux */
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_secure_storage_simple),
      cmocka_unit_test(test_secure_storage_malformed_cache),
      cmocka_unit_test(test_secure_storage_two_keys),
      cmocka_unit_test(test_secure_storage_xdg_cache_home),
      cmocka_unit_test(test_secure_storage_home_dir),
      cmocka_unit_test(test_secure_storage_c_api),
      cmocka_unit_test(test_secure_storage_file_key_is_final_v2_key),
      cmocka_unit_test(test_file_lock_fails_while_held),
      cmocka_unit_test(test_file_lock_released_and_lock_file_persists),
      cmocka_unit_test(test_secure_storage_leftover_lock_file_does_not_block),
      cmocka_unit_test(test_secure_storage_rejects_symlinked_cache_file),
      cmocka_unit_test(test_secure_storage_rejects_world_readable_cache_file_untouched),
      cmocka_unit_test(test_secure_storage_invalid_cache_dir_env_does_not_fall_back),
      cmocka_unit_test(test_secure_storage_empty_env_falls_through),
      cmocka_unit_test(test_secure_storage_file_name_override),
      cmocka_unit_test(test_secure_storage_file_name_override_rejects_path),
      cmocka_unit_test(test_secure_storage_update_key),
      cmocka_unit_test(test_secure_storage_fails_to_find_cache_path),
      cmocka_unit_test(test_get_cache_dir_bad_path),
      cmocka_unit_test(test_get_cache_dir_not_a_dir)
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
