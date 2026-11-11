#include "config.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace {

// Far larger than any real configuration.
const size_t kMaxConfig = 64 * 1024;

std::string guid(const json &j, const char *key) {
  std::string value = j.at(key).get<std::string>();
  if (!is_guid(value)) {
    throw std::invalid_argument(std::string(key) + " is not a GUID");
  }
  return value;
}

// Reads the file, refusing a symlink, a non-regular file and, when running as
// root, a file that root does not own or that others can write: whoever can
// edit it decides who may sudo.
std::string read_config(const std::string &path) {
  int fd = open(path.c_str(),  // Flawfinder: ignore
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error("cannot open " + path);
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      (geteuid() == 0 &&
       (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0))) {
    close(fd);
    throw std::runtime_error(path +
                             " must be a regular file owned by root and "
                             "writable by root only");
  }
  std::string content;
  std::array<char, 4096> chunk;
  for (;;) {
    // Bounded by chunk's size; the total is capped below.
    ssize_t n = read(fd, chunk.data(), chunk.size());  // Flawfinder: ignore
    if (n <= 0 || content.size() + static_cast<size_t>(n) > kMaxConfig) {
      close(fd);
      if (n == 0) {
        return content;
      }
      throw std::runtime_error("cannot read " + path);
    }
    content.append(chunk.data(), static_cast<size_t>(n));
  }
}

// Mapping an Entra account to root, or to another account with UID 0, would
// make one sign-in a root login; sudo already makes any mapped user root for
// the commands sudoers allows.
bool is_superuser(const std::string &user) {
  if (user == "root") {
    return true;
  }
  struct passwd entry, *result = nullptr;
  std::vector<char> buffer(16384);
  return getpwnam_r(user.c_str(), &entry, buffer.data(), buffer.size(),
                    &result) == 0 &&
         result != nullptr && entry.pw_uid == 0;
}

}  // namespace

bool is_guid(const std::string &value) {
  static const std::regex pattern(
      "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
  return std::regex_match(value, pattern);
}

void Config::load(const std::string &path) {
  json j = json::parse(read_config(path));

  tenant_id = guid(j, "tenant_id");
  client_id = guid(j, "client_id");

  const json &age = j.at("max_auth_age");
  if (!age.is_number_integer() || age.get<int64_t>() <= 0 ||
      age.get<int64_t>() > 3600) {
    throw std::invalid_argument("max_auth_age must be 1-3600 seconds");
  }
  max_auth_age = age.get<int64_t>();

  required_amr = j.at("required_amr").get<std::vector<std::string>>();
  if (required_amr.empty()) {
    throw std::invalid_argument("required_amr must not be empty");
  }
  for (const auto &method : required_amr) {
    if (method.empty()) {
      throw std::invalid_argument("required_amr holds an empty method");
    }
  }

  users.clear();
  for (auto &entry : j.at("users").items()) {
    if (!is_guid(entry.key())) {
      throw std::invalid_argument("users key is not an object ID");
    }
    for (auto &local : entry.value()) {
      std::string user = local.get<std::string>();
      if (user.empty() || is_superuser(user)) {
        throw std::invalid_argument(
            "users may not map to an empty name, "
            "root or another UID 0 account");
      }
      users[entry.key()].insert(user);
    }
  }
  if (users.empty()) {
    throw std::invalid_argument("users must not be empty");
  }
}
