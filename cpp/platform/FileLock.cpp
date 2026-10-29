/*
 * File:   FileLock.cpp *
 */

#include "snowflake/FileLock.hpp"

#ifndef _WIN32

#include <algorithm>
#include <cerrno>
#include <random>
#include <thread>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include "../logger/SFLogger.hpp"

namespace Snowflake {

namespace Client {

  using Snowflake::Client::SFLogger;

  namespace {
    constexpr const char *lock_suffix = ".lck";
  }

  FileLock::FileLock(const std::string &path_, int maxAttempts, std::chrono::milliseconds baseDelay)
      : path{path_ + lock_suffix},
        fd(-1),
        locked(false)
  {
    fd = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == -1)
    {
      CXX_LOG_ERROR("Failed to open lock file(path=%s), errno=%d", path.c_str(), errno);
      return;
    }

    std::random_device seed;
    std::mt19937 rng(seed());
    const std::chrono::milliseconds maxDelay = baseDelay * 16;
    std::chrono::milliseconds delay = baseDelay;

    for (int attempt = 1; attempt <= maxAttempts; attempt++)
    {
      if (flock(fd, LOCK_EX | LOCK_NB) == 0)
      {
        locked = true;
        CXX_LOG_DEBUG("Acquired file lock(path=%s)", path.c_str());
        return;
      }
      if (errno != EWOULDBLOCK && errno != EINTR)
      {
        CXX_LOG_ERROR("Failed to acquire file lock(path=%s), errno=%d", path.c_str(), errno);
        return;
      }
      if (attempt == maxAttempts)
      {
        break;
      }

      std::chrono::milliseconds upper = std::min(delay * 3, maxDelay);
      std::uniform_int_distribution<long long> dist(baseDelay.count(), std::max(upper, baseDelay).count());
      delay = std::chrono::milliseconds(dist(rng));
      std::this_thread::sleep_for(delay);
    }

    CXX_LOG_ERROR("Failed to acquire file lock(path=%s) after %d attempts", path.c_str(), maxAttempts);
  }

  FileLock::~FileLock() {
    if (fd == -1)
    {
      return;
    }
    if (locked)
    {
      flock(fd, LOCK_UN);
      CXX_LOG_DEBUG("Released file lock(path=%s)", path.c_str());
    }
    close(fd);
  }
}

}

#endif
