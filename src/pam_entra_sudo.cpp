#include "pam_entra_sudo.hpp"

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace {

const char kDefaultConfig[] = "/etc/pam_entra_sudo.json";
const int64_t kClockSkew = 60;

std::string endpoint(const Config &config, const std::string &path) {
  return std::string(ENTRA_AUTHORITY) + "/" + config.tenant_id + path;
}

// Signals that ask sudo to stop. sudo-rs blocks SIGINT and SIGQUIT while it
// authenticates and classic sudo catches them, so neither would interrupt a
// wait; StopSignals blocks them all and the waits poll for them instead.
const int kStopSignals[] = {SIGINT, SIGQUIT, SIGTERM, SIGHUP};

sigset_t stop_set() {
  sigset_t set;
  sigemptyset(&set);
  for (int sig : kStopSignals) {
    sigaddset(&set, sig);
  }
  return set;
}

// The helper's location; tests point it at their own build.
#ifndef ENTRA_FETCH
#define ENTRA_FETCH "/usr/libexec/pam-entra-sudo/fetch"
#endif

void close_quietly(int fd) {
  if (fd >= 0) {
    close(fd);
  }
}

// The account the helper runs as when the module runs as root.
struct Account {
  uid_t uid;
  gid_t gid;
};

Account unprivileged_account() {
  struct passwd entry, *result = nullptr;
  std::vector<char> buffer(16384);
  if (getpwnam_r("nobody", &entry, buffer.data(), buffer.size(), &result) !=
          0 ||
      result == nullptr || entry.pw_uid == 0 || entry.pw_gid == 0) {
    throw std::runtime_error("no unprivileged account 'nobody'");
  }
  return {entry.pw_uid, entry.pw_gid};
}

// Runs in the forked child: only async-signal-safe calls until execve.
[[noreturn]] void exec_helper(int in, int out, bool drop, Account account,
                              char *const argv[]) {
  if (dup2(in, STDIN_FILENO) < 0 || dup2(out, STDOUT_FILENO) < 0) {
    _exit(127);
  }
  // A fixed path, opened write-only for stderr.
  int null = open("/dev/null", O_WRONLY);  // Flawfinder: ignore
  if (null < 0 || dup2(null, STDERR_FILENO) < 0) {
    _exit(127);
  }
  // Nothing of sudo's (terminal, logs, sockets) may reach the helper.
  const int64_t open_max = sysconf(_SC_OPEN_MAX);
  const int64_t limit = open_max > 0 && open_max < 65536 ? open_max : 65536;
  for (int64_t fd = 3; fd < limit; ++fd) {
    close(static_cast<int>(fd));
  }
  sigset_t none;
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, nullptr);
  signal(SIGPIPE, SIG_DFL);
  if (drop) {
    if (setgroups(0, nullptr) != 0 || setgid(account.gid) != 0 ||
        setuid(account.uid) != 0 || getuid() != account.uid ||
        geteuid() != account.uid || setuid(0) == 0) {
      _exit(127);
    }
  }
  char *const empty_environment[] = {nullptr};
  execve(ENTRA_FETCH, argv, empty_environment);
  _exit(127);
}

}  // namespace

std::string post_form(const std::string &url, const std::string &body) {
  if (body.size() > kMaxRequest) {
    throw std::runtime_error("request too large");
  }
  const bool drop = geteuid() == 0;
  const Account account = drop ? unprivileged_account() : Account{0, 0};
  std::string helper = ENTRA_FETCH, target = url;
  char *const argv[] = {&helper[0], &target[0], nullptr};

  int in[2] = {-1, -1}, out[2] = {-1, -1};
  if (pipe2(in, O_CLOEXEC) != 0 || pipe2(out, O_CLOEXEC) != 0) {
    close_quietly(in[0]);
    close_quietly(in[1]);
    throw std::runtime_error("pipe failed");
  }
  // The body is far smaller than a pipe buffer, so this cannot block, and
  // writing before the fork means no SIGPIPE if the helper dies early.
  ssize_t written = write(in[1], body.data(), body.size());
  close(in[1]);
  if (written != static_cast<ssize_t>(body.size())) {
    close(in[0]);
    close(out[0]);
    close(out[1]);
    throw std::runtime_error("writing the request failed");
  }

  pid_t pid = fork();
  if (pid == 0) {
    exec_helper(in[0], out[1], drop, account, argv);
  }
  close(in[0]);
  close(out[1]);
  if (pid < 0) {
    close(out[0]);
    throw std::runtime_error("fork failed");
  }

  std::string response;
  bool too_large = false, timed_out = false, interrupted = false;
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::seconds(kRequestTimeout + 5);
  std::array<char, 4096> chunk;
  for (;;) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count();
    if (left <= 0) {
      timed_out = true;
      break;
    }
    if (stop_requested()) {
      interrupted = true;
      break;
    }
    struct pollfd p = {out[0], POLLIN, 0};
    int ready = poll(&p, 1, static_cast<int>(std::min<int64_t>(left, 200)));
    if (ready < 0 && errno == EINTR) {
      continue;
    }
    if (ready == 0) {
      continue;
    }
    if (ready < 0) {
      break;
    }
    // Bounded by chunk's size; the total is capped below.
    ssize_t n = read(out[0], chunk.data(), chunk.size());  // Flawfinder: ignore
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      break;
    }
    if (response.size() + static_cast<size_t>(n) > kMaxResponse) {
      too_large = true;
      break;
    }
    response.append(chunk.data(), static_cast<size_t>(n));
  }
  close(out[0]);
  if (timed_out || too_large || interrupted) {
    kill(pid, SIGKILL);
  }
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (interrupted) {
    throw Interrupted();
  }
  if (timed_out) {
    throw std::runtime_error("request timed out");
  }
  if (too_large) {
    throw std::runtime_error("response too large");
  }
  // Fails closed if someone else reaped the helper (ECHILD).
  if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    throw std::runtime_error("request failed (helper status " +
                             std::to_string(waited == pid && WIFEXITED(status)
                                                ? WEXITSTATUS(status)
                                                : -1) +
                             ")");
  }
  return response;
}

bool stop_requested() {
  sigset_t pending;
  if (sigpending(&pending) != 0) {
    return false;
  }
  for (int sig : kStopSignals) {
    if (sigismember(&pending, sig) == 1) {
      return true;
    }
  }
  return false;
}

StopSignals::StopSignals() {
  sigset_t set = stop_set();
  pthread_sigmask(SIG_BLOCK, &set, &saved_);
}

StopSignals::~StopSignals() {
  // A stop signal that arrived while blocked has been acted on (the module
  // returns PAM_ABORT), so it is consumed rather than delivered to sudo.
  sigset_t set = stop_set();
  struct timespec zero = {0, 0};
  while (stop_requested() && sigtimedwait(&set, nullptr, &zero) > 0) {
  }
  pthread_sigmask(SIG_SETMASK, &saved_, nullptr);
}

namespace {

// Sleeps until `until`, waking early (and throwing) on a stop signal.
void wait_until(std::chrono::steady_clock::time_point until) {
  for (;;) {
    if (stop_requested()) {
      throw Interrupted();
    }
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    until - std::chrono::steady_clock::now())
                    .count();
    if (left <= 0) {
      return;
    }
    int64_t slice = std::min<int64_t>(left, 200);
    struct timespec ts = {static_cast<time_t>(slice / 1000),
                          static_cast<int64_t>(slice % 1000) * 1000000};
    nanosleep(&ts, nullptr);
  }
}

// A JSON integer that fits int64_t; anything else (floats, huge unsigned
// values) throws, so no claim arithmetic can overflow.
int64_t integer(const json &value) {
  if (!value.is_number_integer() ||
      (value.is_number_unsigned() &&
       value.get<uint64_t>() >
           static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))) {
    throw std::invalid_argument("not a 64-bit integer");
  }
  return value.get<int64_t>();
}

std::string url_escape(const std::string &value) {
  static const char hex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : value) {
    if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0F]);
    }
  }
  return out;
}

std::string base64url_decode(const std::string &in) {
  static const std::string alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  uint32_t value = 0;
  int bits = -8;
  for (char c : in) {
    size_t pos = alphabet.find(c);
    if (pos == std::string::npos) {
      throw std::invalid_argument("invalid base64url");
    }
    value = ((value << 6) | static_cast<uint32_t>(pos)) & 0xFFFFFFu;
    bits += 6;
    if (bits >= 0) {
      out.push_back(static_cast<char>((value >> bits) & 0xFF));
      bits -= 8;
    }
  }
  return out;
}

std::string printable(const std::string &in) {
  std::string out;
  for (char c : in) {
    if (c >= 0x20 && c <= 0x7e) {
      out.push_back(c);
    }
  }
  return out;
}

}  // namespace

DeviceCode request_device_code(const Config &config) {
  std::string body = "client_id=" + config.client_id +
                     "&scope=openid%20profile&prompt=login&max_age=0";
  json response =
      json::parse(post_form(endpoint(config, "/oauth2/v2.0/devicecode"), body));
  if (response.contains("error")) {
    throw std::runtime_error("device code request refused: " +
                             response["error"].get<std::string>());
  }
  DeviceCode code;
  code.device_code = response.at("device_code").get<std::string>();
  code.user_code = response.at("user_code").get<std::string>();
  code.verification_uri = response.at("verification_uri").get<std::string>();
  code.expires_in =
      std::clamp<int64_t>(integer(response.at("expires_in")), 1, 3600);
  if (response.contains("interval")) {
    code.interval = std::clamp<int64_t>(integer(response["interval"]), 1, 30);
  }
  return code;
}

std::string poll_for_id_token(const Config &config, const DeviceCode &code,
                              int64_t timeout_seconds) {
  std::string body =
      "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=" +
      config.client_id + "&device_code=" + url_escape(code.device_code);
  std::string url = endpoint(config, "/oauth2/v2.0/token");
  using clock = std::chrono::steady_clock;
  // A wall-clock bound: each request may add at most its own timeout.
  const clock::time_point deadline =
      clock::now() +
      std::chrono::seconds(std::min(timeout_seconds, code.expires_in));
  int64_t interval = code.interval;
  int failures = 0;
  for (;;) {
    wait_until(
        std::min(deadline, clock::now() + std::chrono::seconds(interval)));
    if (clock::now() >= deadline) {
      throw std::runtime_error("timed out waiting for sign-in");
    }
    json response;
    try {
      response = json::parse(post_form(url, body));
    } catch (const Interrupted &) {
      throw;
    } catch (const std::exception &) {
      // One failed poll should not cost the user a sign-in in progress.
      if (++failures >= kMaxPollFailures) {
        throw;
      }
      continue;
    }
    failures = 0;
    if (response.contains("id_token")) {
      return response["id_token"].get<std::string>();
    }
    std::string error = response.value("error", "");
    if (error == "slow_down") {
      interval = std::min<int64_t>(interval + 5, 30);
    } else if (error != "authorization_pending") {
      throw std::runtime_error(
          "token request refused: " +
          (error.empty() ? "no id_token" : printable(error)));
    }
  }
}

bool validate_id_token(const std::string &id_token, const Config &config,
                       int64_t now, std::string *oid, std::string *reason) {
  size_t first = id_token.find('.');
  size_t second =
      first == std::string::npos ? first : id_token.find('.', first + 1);
  if (second == std::string::npos) {
    *reason = "malformed id_token";
    return false;
  }
  json claims;
  try {
    claims = json::parse(
        base64url_decode(id_token.substr(first + 1, second - first - 1)));
  } catch (const std::exception &) {
    *reason = "unreadable id_token payload";
    return false;
  }
  try {
    std::string issuer = endpoint(config, "/v2.0");
    if (claims.at("iss").get<std::string>() != issuer) {
      *reason = "unexpected issuer";
      return false;
    }
    if (claims.at("tid").get<std::string>() != config.tenant_id) {
      *reason = "unexpected tenant";
      return false;
    }
    if (claims.at("aud").get<std::string>() != config.client_id) {
      *reason = "unexpected audience";
      return false;
    }
    // now is a current Unix time, so with both values positive none of the
    // comparisons below can overflow.
    int64_t exp = integer(claims.at("exp"));
    if (exp <= 0 || exp < now - kClockSkew) {
      *reason = "id_token expired";
      return false;
    }
    if (!claims.contains("auth_time")) {
      *reason = "no auth_time, sign-in was not fresh";
      return false;
    }
    int64_t auth_time = integer(claims["auth_time"]);
    if (auth_time <= 0) {
      *reason = "invalid auth_time";
      return false;
    }
    if (auth_time > now + kClockSkew) {
      *reason = "auth_time in the future";
      return false;
    }
    if (now - auth_time > config.max_auth_age) {
      *reason = "sign-in " + std::to_string(now - auth_time) + "s old, limit " +
                std::to_string(config.max_auth_age) + "s";
      return false;
    }
    std::vector<std::string> amr;
    if (claims.contains("amr")) {
      amr = claims["amr"].get<std::vector<std::string>>();
    }
    for (const auto &method : config.required_amr) {
      if (std::find(amr.begin(), amr.end(), method) == amr.end()) {
        *reason = "amr lacks required method " + method;
        return false;
      }
    }
    std::string object_id = claims.at("oid").get<std::string>();
    if (!is_guid(object_id)) {
      *reason = "oid is not an object ID";
      return false;
    }
    *oid = object_id;
  } catch (const std::exception &) {
    *reason = "missing or mistyped claim";
    return false;
  }
  return true;
}

bool is_authorized(const Config &config, const std::string &oid,
                   const std::string &local_user) {
  auto entry = config.users.find(oid);
  return entry != config.users.end() && entry->second.count(local_user) > 0;
}

bool is_mapped(const Config &config, const std::string &local_user) {
  for (const auto &entry : config.users) {
    if (entry.second.count(local_user) > 0) {
      return true;
    }
  }
  return false;
}

std::string prompt_text(const std::string &host, const DeviceCode &code) {
  return "sudo on " + printable(host) + ": sign in at " +
         printable(code.verification_uri) + " with code " +
         printable(code.user_code) + "\nWaiting for the sign-in...";
}

namespace {

void show_info(pam_handle_t *pamh, const std::string &text) {
  const struct pam_conv *conv = nullptr;
  if (pam_get_item(pamh, PAM_CONV, reinterpret_cast<const void **>(&conv)) !=
          PAM_SUCCESS ||
      conv == nullptr || conv->conv == nullptr) {
    throw std::runtime_error("no PAM conversation");
  }
  struct pam_message message;
  message.msg_style = PAM_TEXT_INFO;
  message.msg = text.c_str();
  const struct pam_message *messages = &message;
  struct pam_response *responses = nullptr;
  int rc = conv->conv(1, &messages, &responses, conv->appdata_ptr);
  if (responses != nullptr) {
    free(responses->resp);
    free(responses);
  }
  if (rc != PAM_SUCCESS) {
    throw std::runtime_error("PAM conversation failed");
  }
}

std::string hostname() {
  struct utsname name;
  if (uname(&name) != 0) {
    return "unknown host";
  }
  return name.nodename;
}

std::string item(pam_handle_t *pamh, int type) {
  const void *value = nullptr;
  if (pam_get_item(pamh, type, &value) != PAM_SUCCESS || value == nullptr) {
    return "";
  }
  return printable(static_cast<const char *>(value));
}

// sudo's own command line (for example "sudo systemctl restart x"), for the
// audit log.
std::string command_line() {
  std::ifstream in("/proc/self/cmdline", std::ios::binary);
  std::string raw((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
  std::replace(raw.begin(), raw.end(), '\0', ' ');
  std::string command = printable(raw);
  if (command.size() > 300) {
    command = command.substr(0, 300) + "...";
  }
  return command;
}

int authenticate(pam_handle_t *pamh, const std::string &config_path) {
  Config config;
  config.load(config_path);

  const char *user = nullptr;
  if (pam_get_user(pamh, &user, nullptr) != PAM_SUCCESS || user == nullptr) {
    throw std::runtime_error("pam_get_user failed");
  }
  const std::string context =
      "user=" + printable(user) + " tty=" + item(pamh, PAM_TTY) +
      " rhost=" + item(pamh, PAM_RHOST) + " command=\"" + command_line() + "\"";

  // Users nobody mapped never get a code they could not use.
  if (!is_mapped(config, user)) {
    pam_syslog(pamh, LOG_NOTICE, "skipped, not mapped: %s", context.c_str());
    return PAM_AUTH_ERR;
  }

  StopSignals stop;
  try {
    DeviceCode code = request_device_code(config);
    show_info(pamh, prompt_text(hostname(), code));
    std::string id_token = poll_for_id_token(config, code, kSignInTimeout);

    std::string oid, reason;
    if (!validate_id_token(id_token, config,
                           static_cast<int64_t>(std::time(nullptr)), &oid,
                           &reason)) {
      pam_syslog(pamh, LOG_WARNING, "denied: %s: %s", reason.c_str(),
                 context.c_str());
      return PAM_AUTH_ERR;
    }
    if (!is_authorized(config, oid, user)) {
      pam_syslog(pamh, LOG_WARNING, "denied: object ID %s is not mapped: %s",
                 oid.c_str(), context.c_str());
      return PAM_AUTH_ERR;
    }
    pam_syslog(pamh, LOG_NOTICE, "authenticated as object ID %s: %s",
               oid.c_str(), context.c_str());
    return PAM_SUCCESS;
  } catch (const Interrupted &) {
    pam_syslog(pamh, LOG_NOTICE, "interrupted: %s", context.c_str());
    return PAM_ABORT;
  } catch (const std::exception &e) {
    pam_syslog(pamh, LOG_ERR, "denied: %s: %s", printable(e.what()).c_str(),
               context.c_str());
    return PAM_AUTH_ERR;
  }
}

}  // namespace

extern "C" __attribute__((visibility("default"))) int pam_sm_authenticate(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  // No exception may cross into the C caller; every failure denies.
  try {
    return authenticate(pamh, argc > 0 ? argv[0] : kDefaultConfig);
  } catch (const std::exception &e) {
    pam_syslog(pamh, LOG_ERR, "denied: %s", printable(e.what()).c_str());
  } catch (...) {
    pam_syslog(pamh, LOG_ERR, "denied: unknown error");
  }
  return PAM_AUTH_ERR;
}

extern "C" __attribute__((visibility("default"))) int pam_sm_setcred(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}
