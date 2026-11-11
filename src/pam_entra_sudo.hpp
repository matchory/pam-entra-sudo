#ifndef SRC_PAM_ENTRA_SUDO_HPP_
#define SRC_PAM_ENTRA_SUDO_HPP_

#include <signal.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "config.hpp"

// Tests point this at the mock server.
#ifndef ENTRA_AUTHORITY
#define ENTRA_AUTHORITY "https://login.microsoftonline.com"
#endif

// Debian and Ubuntu's bundle from the ca-certificates package.
#ifndef ENTRA_CA_BUNDLE
#define ENTRA_CA_BUNDLE "/etc/ssl/certs/ca-certificates.crt"
#endif

// Entra's requests and responses are a few KiB; anything far larger is not
// one of them.
inline constexpr size_t kMaxRequest = 4096;
inline constexpr size_t kMaxResponse = 64 * 1024;
// Seconds a single HTTP request may take.
inline constexpr long kRequestTimeout = 30;  // NOLINT(runtime/int)

// POSTs a form to url through the pam-entra-sudo-fetch helper, which runs with
// an empty environment and, when called as root, as the user nobody. Returns
// the response body; throws on any failure.
std::string post_form(const std::string &url, const std::string &body);

// Seconds the user has to sign in; consecutive failed polls tolerated.
inline constexpr int64_t kSignInTimeout = 300;
inline constexpr int kMaxPollFailures = 3;

// Thrown when a stop signal (Ctrl-C) arrives while the module waits.
class Interrupted : public std::runtime_error {
 public:
  Interrupted() : std::runtime_error("interrupted") {}
};

// While alive, blocks SIGINT, SIGQUIT, SIGTERM and SIGHUP so that the waits
// in post_form and poll_for_id_token can see them as pending and stop.
class StopSignals {
 public:
  StopSignals();
  ~StopSignals();
  StopSignals(const StopSignals &) = delete;
  StopSignals &operator=(const StopSignals &) = delete;

 private:
  sigset_t saved_;
};

// True if a stop signal is pending (only visible while it is blocked).
bool stop_requested();

// True if any object ID maps to local_user.
bool is_mapped(const Config &config, const std::string &local_user);

struct DeviceCode {
  std::string device_code, user_code, verification_uri;
  int64_t interval = 5, expires_in = 0;
};

// Asks for a device code with prompt=login&max_age=0, so Entra demands a new
// interactive sign-in and puts auth_time in the ID token.
DeviceCode request_device_code(const Config &config);

// Polls the token endpoint until the user signs in, then returns the ID
// token. Throws on denial, expiry or after timeout_seconds.
std::string poll_for_id_token(const Config &config, const DeviceCode &code,
                              int64_t timeout_seconds);

// Checks the ID token's claims against config at time `now` and returns the
// user's object ID (oid) in *oid. On failure returns false with *reason set.
// The signature is not checked: the token comes straight from the token
// endpoint over TLS (OIDC Core 3.1.3.7).
bool validate_id_token(const std::string &id_token, const Config &config,
                       int64_t now, std::string *oid, std::string *reason);

// True if config maps the object ID to the local account.
bool is_authorized(const Config &config, const std::string &oid,
                   const std::string &local_user);

// The text shown to the user. Server-supplied fields are reduced to
// printable ASCII, so they cannot carry terminal escape sequences.
std::string prompt_text(const std::string &host, const DeviceCode &code);

#endif  // SRC_PAM_ENTRA_SUDO_HPP_
