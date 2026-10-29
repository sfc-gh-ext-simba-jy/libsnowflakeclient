#ifndef SNOWFLAKECLIENT_CACHEFILE_HPP
#define SNOWFLAKECLIENT_CACHEFILE_HPP

#include <functional>
#include <string>
#include <vector>

#include <boost/optional.hpp>
#include <picojson.h>

namespace Snowflake {

namespace Client {

  boost::optional<std::string> getCacheDir(const std::string& envVar, const std::vector<std::string>& subPathSegments);

  boost::optional<std::string> getCredentialFilePath();

  /**
   * Reads the cache file into `result`. A missing file, empty content or
   * invalid JSON yields an empty cache and no error. Returns a non-empty error
   * when the file is unsafe (not a regular file, not owned by the effective
   * user, mode other than 0600) or cannot be read.
   */
  std::string readCacheFile(const std::string &path, picojson::value &result);

  /**
   * Opens the cache file once, validates it, parses it, passes the cache to
   * `modify` and writes it back through the same descriptor when `modify`
   * returns true. Invalid JSON is replaced by an empty cache. A missing file is
   * created (O_EXCL, 0600) only when `createIfMissing` is set; otherwise
   * nothing is written. An unsafe file is left untouched and reported as an
   * error.
   */
  std::string updateCacheFile(const std::string &path, bool createIfMissing,
                              const std::function<bool(picojson::value&)> &modify);

  void cacheFileUpdate(picojson::value &cache, const std::string &key, const std::string &credential);

  bool cacheFileRemove(picojson::value &cache, const std::string &key);

  boost::optional<std::string> cacheFileGet(picojson::value &cache, const std::string &key);

}

}

#endif // SNOWFLAKECLIENT_CACHEFILE_HPP
