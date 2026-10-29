/*
 * File:   FileLock.hpp *
 */

#ifndef SNOWFLAKECLIENT_FILELOCK_HPP
#define SNOWFLAKECLIENT_FILELOCK_HPP

#include <chrono>
#include <string>

namespace Snowflake {

namespace Client {

  /**
   * Exclusive advisory lock (flock) on a persistent "<path>.lck" sidecar file.
   *
   * Acquisition retries with decorrelated jitter: each retry sleeps a random
   * duration in [baseDelay, min(3 * previous, 16 * baseDelay)]. The lock is
   * released when the object is destroyed; the .lck file stays on disk.
   * Unix only.
   */
  class FileLock {
  public:
    explicit FileLock(const std::string& path,
                      int maxAttempts = 20,
                      std::chrono::milliseconds baseDelay = std::chrono::milliseconds(100));

    // Disable copying
    FileLock(const FileLock &) = delete;
    FileLock &operator=(const FileLock &) = delete;

    inline bool isLocked() const {
      return locked;
    }

    inline const std::string &getPath() const {
      return path;
    }

    ~FileLock();

  private:
    std::string path;
    int fd;
    bool locked;
  };
}

}

#endif //SNOWFLAKECLIENT_FILELOCK_HPP
