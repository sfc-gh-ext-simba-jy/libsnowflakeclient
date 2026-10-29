#include "CacheFile.hpp"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <picojson.h>
#include <boost/filesystem.hpp>

#include "../logger/SFLogger.hpp"

namespace {
  class FileDescriptor {
  public:
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor operator=(const FileDescriptor&) = delete;
    explicit FileDescriptor(int fd) : m_fd(fd) {}

    ~FileDescriptor() {
      if (m_fd != -1) {
        close(m_fd);
      }
    }
    operator int() const { return m_fd; }
    int get() const { return m_fd; }
  private:
    int m_fd;
  };

  using namespace Snowflake::Client;
  const char* DEFAULT_CREDENTIAL_FILE_NAME = "credential_cache_v2.json";
  const char* CREDENTIAL_FILE_NAME_ENV = "SF_TEMPORARY_CREDENTIAL_CACHE_FILE_NAME";
  const char* CREDENTIAL_DIR_ENV = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR";

  bool mkdirIfNotExists(const std::string& dir, mode_t mode)
  {
    int result = mkdir(dir.c_str(), mode);
    if (result == 0)
    {
      CXX_LOG_DEBUG("Created %s directory.", dir.c_str());
      return true;
    }

    if (errno == EEXIST)
    {
      CXX_LOG_TRACE("Directory %s already exists.", dir.c_str());
      return true;
    }

    CXX_LOG_ERROR("Failed to create %s directory. Error: %d", dir.c_str(), errno);
    return false;

  }

  boost::optional<std::string> getEnv(const std::string& envVar)
  {
    char *root = getenv(envVar.c_str());

    if (root == nullptr || root[0] == '\0')
    {
      return {};
    }

    return std::string(root);
  }

  boost::optional<std::string> getCredentialFileName()
  {
    auto overrideOpt = getEnv(CREDENTIAL_FILE_NAME_ENV);
    if (!overrideOpt)
    {
      return std::string(DEFAULT_CREDENTIAL_FILE_NAME);
    }

    const std::string& name = overrideOpt.get();
    if (name.find('/') != std::string::npos || name == "." || name == "..")
    {
      CXX_LOG_ERROR("%s=%s is not a plain file name.", CREDENTIAL_FILE_NAME_ENV, name.c_str());
      return {};
    }
    return name;
  }

  void ensureObject(picojson::value &val)
  {
    if (!val.is<picojson::object>())
    {
      val = picojson::value(picojson::object());
    }
  }

  picojson::object& getTokens(picojson::value& cache)
  {
    ensureObject(cache);
    auto &obj = cache.get<picojson::object>();
    auto pair = obj.emplace("tokens", picojson::value(picojson::object()));
    auto& tokens = pair.first->second;
    ensureObject(tokens);
    return tokens.get<picojson::object>();
  }

  std::string openError(const std::string &path)
  {
    if (errno == ELOOP)
    {
      return "Irregular file type for cache file(path=" + path + ")";
    }
    return "Failed to open cache file(path=" + path + ", errno=" + std::to_string(errno) + ")";
  }

  std::string ensureSafeFile(const FileDescriptor& fd)
  {
    struct stat s = {};
    if (fstat(fd, &s) == -1)
    {
      return "fstat failed with errno=" + std::to_string(errno);
    }

    if (!S_ISREG(s.st_mode))
    {
      return "Cache file is not a regular file";
    }

    if (s.st_uid != geteuid())
    {
      return "Cache file is not owned by effective user";
    }

    if ((s.st_mode & 0777) != 0600)
    {
      char mode[8];
      snprintf(mode, sizeof(mode), "%o", static_cast<unsigned>(s.st_mode & 0777));
      return std::string("Cache file permissions are ") + mode + " instead of 600";
    }

    return {};
  }

  std::string readAll(const FileDescriptor& fd, std::string &contents)
  {
    if (lseek(fd, 0, SEEK_SET) == -1)
    {
      return "Failed to seek start of cache file, errno=" + std::to_string(errno);
    }

    contents.clear();
    char buf[4096];
    while (true)
    {
      ssize_t bytesRead = read(fd, buf, sizeof(buf));
      if (bytesRead == -1)
      {
        if (errno == EINTR)
        {
          continue;
        }
        return "Failed to read cache file, errno=" + std::to_string(errno);
      }
      if (bytesRead == 0)
      {
        return {};
      }
      contents.append(buf, static_cast<size_t>(bytesRead));
    }
  }

  void parseLenient(const std::string &contents, const std::string &path, picojson::value &result)
  {
    if (contents.empty())
    {
      result = picojson::value(picojson::object());
      return;
    }

    std::string error = picojson::parse(result, contents);
    if (!error.empty())
    {
      CXX_LOG_WARN("Cache file(path=%s) is not valid JSON, treating it as empty. Error: %s", path.c_str(), error.c_str());
      result = picojson::value(picojson::object());
    }
  }

  std::string writeAll(const FileDescriptor& fd, const std::string &buf)
  {
    if (lseek(fd, 0, SEEK_SET) == -1)
    {
      return "Failed to seek start of cache file, errno=" + std::to_string(errno);
    }
    if (ftruncate(fd, 0) == -1)
    {
      return "Failed to truncate cache file, errno=" + std::to_string(errno);
    }

    size_t written = 0;
    while (written < buf.size())
    {
      ssize_t n = write(fd, buf.data() + written, buf.size() - written);
      if (n == -1)
      {
        if (errno == EINTR)
        {
          continue;
        }
        return "Failed to write cache file, errno=" + std::to_string(errno);
      }
      written += static_cast<size_t>(n);
    }

    if (fsync(fd) == -1)
    {
      return "Failed to flush cache file, errno=" + std::to_string(errno);
    }
    return {};
  }
}

namespace Snowflake {

namespace Client {
  boost::optional<std::string> getCacheDir(const std::string& envVar, const std::vector<std::string>& subPathSegments)
  {
    auto envVarValueOpt = getEnv(envVar);
    if (!envVarValueOpt)
    {
      return {};
    }

    const std::string& envVarValue = envVarValueOpt.get();

    struct stat s = {};
    int err = stat(envVarValue.c_str(), &s);

    if (err != 0)
    {
      CXX_LOG_INFO("Failed to stat %s=%s, errno=%d.", envVar.c_str(), envVarValue.c_str(), errno);
      return {};
    }

    if (!S_ISDIR(s.st_mode))
    {
      CXX_LOG_INFO("%s=%s is not a directory.", envVar.c_str(), envVarValue.c_str());
      return {};
    }

    auto cacheDir = envVarValue;
    for (const auto &segment: subPathSegments) {
      if (!mkdirIfNotExists(cacheDir, 0700)) {
        CXX_LOG_INFO("Could not create cache dir=%s.", cacheDir.c_str());
        return {};
      }
      cacheDir.append(PATH_SEP + segment);
    }

    if (!mkdirIfNotExists(cacheDir, 0700)) {
      CXX_LOG_INFO("Could not create cache dir=%s.", cacheDir.c_str());
      return {};
    }

    err = stat(cacheDir.c_str(), &s);

    if (err != 0)
    {
      CXX_LOG_INFO("Failed to stat %s, errno=%d.", cacheDir.c_str(), errno);
      return {};
    }

    if (!S_ISDIR(s.st_mode))
    {
      CXX_LOG_INFO("%s is not a directory.", cacheDir.c_str());
      return {};
    }

    if (s.st_uid != geteuid())
    {
      CXX_LOG_INFO("%s is not owned by effective user.", cacheDir.c_str());
      return {};
    }

    if ((s.st_mode & 0777) != 0700)
    {
      CXX_LOG_INFO("%s has incorrect permissions.", cacheDir.c_str());
      return {};
    }

    return cacheDir;
  }

  boost::optional<std::string> getCredentialFilePath()
  {
    auto fileNameOpt = getCredentialFileName();
    if (!fileNameOpt)
    {
      return {};
    }

    boost::optional<std::string> directory;
    if (getEnv(CREDENTIAL_DIR_ENV))
    {
      directory = getCacheDir(CREDENTIAL_DIR_ENV, {});
      if (!directory)
      {
        CXX_LOG_ERROR("%s is set but is not a usable cache directory.", CREDENTIAL_DIR_ENV);
        return {};
      }
    }
    else
    {
      directory = getCacheDir("XDG_CACHE_HOME", {"snowflake"});
      if (!directory)
      {
        directory = getCacheDir("HOME", {".cache", "snowflake"});
      }
    }

    if (!directory)
    {
      return {};
    }

    auto path = directory.get() + PATH_SEP + fileNameOpt.get();
    CXX_LOG_TRACE("Successfully found credential file path=%s", path.c_str());
    return path;
  }

  std::string readCacheFile(const std::string &path, picojson::value &result) {
    FileDescriptor fd{open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    if (fd == -1) {
      if (errno == ENOENT) {
        result = picojson::value(picojson::object());
        return {};
      }
      return openError(path);
    }

    std::string error = ensureSafeFile(fd);
    if (!error.empty())
    {
      return error + " (path=" + path + ")";
    }

    std::string contents;
    error = readAll(fd, contents);
    if (!error.empty())
    {
      return error + " (path=" + path + ")";
    }

    parseLenient(contents, path, result);
    return {};
  }

  std::string updateCacheFile(const std::string &path, bool createIfMissing,
                              const std::function<bool(picojson::value&)> &modify) {
    bool created = false;
    int rawFd = open(path.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (rawFd == -1 && errno == ENOENT)
    {
      if (!createIfMissing)
      {
        return {};
      }
      rawFd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
      created = true;
    }
    if (rawFd == -1)
    {
      return openError(path);
    }
    FileDescriptor fd{rawFd};

    if (created && fchmod(fd, 0600) == -1)
    {
      return "Failed to set permissions on new cache file(path=" + path + ", errno=" + std::to_string(errno) + ")";
    }

    std::string error = ensureSafeFile(fd);
    if (!error.empty())
    {
      return error + " (path=" + path + ")";
    }

    std::string contents;
    error = readAll(fd, contents);
    if (!error.empty())
    {
      return error + " (path=" + path + ")";
    }

    picojson::value cache;
    parseLenient(contents, path, cache);
    if (!modify(cache))
    {
      return {};
    }

    error = writeAll(fd, cache.serialize());
    if (!error.empty())
    {
      return error + " (path=" + path + ")";
    }
    return {};
  }

  void cacheFileUpdate(picojson::value &cache, const std::string &key, const std::string &credential)
  {
    picojson::object& tokens = getTokens(cache);
    tokens[key] = picojson::value(credential);
  }

  bool cacheFileRemove(picojson::value &cache, const std::string &key)
  {
    picojson::object& tokens = getTokens(cache);
    return tokens.erase(key) > 0;
  }

  boost::optional<std::string> cacheFileGet(picojson::value &cache, const std::string &key) {
    picojson::object& tokens = getTokens(cache);
    auto it = tokens.find(key);

    if (it == tokens.end())
    {
      return {};
    }

    if (!it->second.is<std::string>())
    {
      return {};
    }

    return it->second.get<std::string>();
  }

}

}
