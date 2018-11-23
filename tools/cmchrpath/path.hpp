///
#ifndef SSHD_RPATH_PATH_HPP
#define SSHD_RPATH_PATH_HPP
#include <climits>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>
#if defined(__linux__)
#define symlinkEntrypointExecutable "/proc/self/exe"
#elif !defined(__APPLE__)
#define symlinkEntrypointExecutable "/proc/curproc/exe"
#endif
namespace ssh {

inline bool GetExecutableAbsolutePath(std::string &entrypointExecutable) {
  bool result = false;

  entrypointExecutable.clear();

// Get path to the executable for the current process using
// platform specific means.
#if defined(__linux__) || (defined(__NetBSD__) && !defined(KERN_PROC_PATHNAME))
  // On Linux, fetch the entry point EXE absolute path, inclusive of filename.
  char exe[PATH_MAX];
  ssize_t res = readlink(symlinkEntrypointExecutable, exe, PATH_MAX - 1);
  if (res != -1) {
    exe[res] = '\0';
    entrypointExecutable.assign(exe);
    result = true;
  } else {
    result = false;
  }
#elif defined(__APPLE__)

  // On Mac, we ask the OS for the absolute path to the entrypoint executable
  uint32_t lenActualPath = 0;
  if (_NSGetExecutablePath(nullptr, &lenActualPath) == -1) {
    // OSX has placed the actual path length in lenActualPath,
    // so re-attempt the operation
    std::string resizedPath(lenActualPath, '\0');
    char *pResizedPath = const_cast<char *>(resizedPath.c_str());
    if (_NSGetExecutablePath(pResizedPath, &lenActualPath) == 0) {
      entrypointExecutable.assign(pResizedPath);
      result = true;
    }
  }
#elif defined(__FreeBSD__)
  static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
  char path[PATH_MAX];
  size_t len;

  len = sizeof(path);
  if (sysctl(name, 4, path, &len, nullptr, 0) == 0) {
    entrypointExecutable.assign(path);
    result = true;
  } else {
    // ENOMEM
    result = false;
  }
#elif defined(__NetBSD__) && defined(KERN_PROC_PATHNAME)
  static const int name[] = {
      CTL_KERN,
      KERN_PROC_ARGS,
      -1,
      KERN_PROC_PATHNAME,
  };
  char path[MAXPATHLEN];
  size_t len;

  len = sizeof(path);
  if (sysctl(name, __arraycount(name), path, &len, NULL, 0) != -1) {
    entrypointExecutable.assign(path);
    result = true;
  } else {
    result = false;
  }
#else
  // On non-Mac OS, return the symlink that will be resolved by GetAbsolutePath
  // to fetch the entrypoint EXE absolute path, inclusive of filename.
  entrypointExecutable.assign(symlinkEntrypointExecutable);
  result = true;
#endif

  return result;
}

inline std::vector<std::string_view> PathSplit(std::string_view sv) {
  std::vector<std::string_view> output;
  size_t first = 0;
  while (first < sv.size()) {
    const auto second = sv.find_first_of('/', first);
    if (first != second) {
      auto s = sv.substr(first, second - first);
      if (s == "..") {
        if (!output.empty()) {
          output.pop_back();
        }
      } else if (s != ".") {
        output.emplace_back(s);
      }
    }
    if (second == std::string_view::npos) {
      break;
    }
    first = second + 1;
  }
  return output;
}

std::string PathCanonicalize(const std::string &s) {
  auto av = PathSplit(s);
  std::string s2("/");
  for (auto a : av) {
    s2.append(a.data(), a.size()).append("/");
  }
  if (s2.size() > 2) {
    s2.pop_back();
  }
  return s2;
}

} // namespace ssh

#endif
