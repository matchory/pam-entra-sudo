#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <string>

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"
#include "pam_entra_sudo.hpp"

using json = nlohmann::json;

namespace {

const char kTenant[] = "11111111-2222-3333-4444-555555555555";
const char kClient[] = "66666666-7777-8888-9999-000000000000";
const char kOid[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const int64_t kNow = 1800000000;

Config config() {
  Config c;
  c.tenant_id = kTenant;
  c.client_id = kClient;
  c.max_auth_age = 120;
  c.required_amr = {"fido"};
  c.users[kOid] = {"alice"};
  return c;
}

std::string b64url(const std::string &in) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  uint32_t value = 0;
  int bits = -6;
  for (unsigned char c : in) {
    value = ((value << 8) | c) & 0xFFFFFFu;
    bits += 8;
    while (bits >= 0) {
      out.push_back(alphabet[(value >> bits) & 0x3F]);
      bits -= 6;
    }
  }
  if (bits > -6) {
    out.push_back(alphabet[((value << 8) >> (bits + 8)) & 0x3Fu]);
  }
  return out;
}

json claims() {
  return {{"iss", std::string(ENTRA_AUTHORITY) + "/" + kTenant + "/v2.0"},
          {"tid", kTenant},
          {"aud", kClient},
          {"exp", kNow + 3600},
          {"auth_time", kNow - 10},
          {"amr", {"fido", "mfa"}},
          {"oid", kOid}};
}

std::string token(const json &payload) {
  return b64url(R"({"alg":"none"})") + "." + b64url(payload.dump()) + ".sig";
}

// Validates a token built from claims() after `edit`, returning the reason
// ("" on success).
template <typename Edit>
std::string check(Edit edit) {
  json payload = claims();
  edit(&payload);
  std::string oid, reason;
  bool ok = validate_id_token(token(payload), config(), kNow, &oid, &reason);
  if (ok) {
    EXPECT_EQ(oid, kOid);
    EXPECT_TRUE(reason.empty());
  } else {
    EXPECT_FALSE(reason.empty());
  }
  return ok ? "" : reason;
}

TEST(IdTokenTest, Valid) {
  EXPECT_EQ(check([](json *) {}), "");
}

TEST(IdTokenTest, WrongIssuer) {
  EXPECT_EQ(check([](json *p) {
              (*p)["iss"] = "https://login.microsoftonline.com/other/v2.0";
            }),
            "unexpected issuer");
}

TEST(IdTokenTest, WrongTenant) {
  EXPECT_EQ(check([](json *p) { (*p)["tid"] = "other"; }), "unexpected tenant");
}

TEST(IdTokenTest, WrongAudience) {
  EXPECT_EQ(check([](json *p) { (*p)["aud"] = "other"; }),
            "unexpected audience");
}

TEST(IdTokenTest, Expired) {
  EXPECT_EQ(check([](json *p) { (*p)["exp"] = kNow - 61; }),
            "id_token expired");
}

TEST(IdTokenTest, ExpiredWithinSkew) {
  EXPECT_EQ(check([](json *p) { (*p)["exp"] = kNow - 59; }), "");
}

TEST(IdTokenTest, NoAuthTime) {
  EXPECT_EQ(check([](json *p) { p->erase("auth_time"); }),
            "no auth_time, sign-in was not fresh");
}

TEST(IdTokenTest, StaleSignIn) {
  EXPECT_EQ(check([](json *p) { (*p)["auth_time"] = kNow - 121; }),
            "sign-in 121s old, limit 120s");
}

TEST(IdTokenTest, SignInAtLimit) {
  EXPECT_EQ(check([](json *p) { (*p)["auth_time"] = kNow - 120; }), "");
}

TEST(IdTokenTest, SignInInFuture) {
  EXPECT_EQ(check([](json *p) { (*p)["auth_time"] = kNow + 61; }),
            "auth_time in the future");
}

TEST(IdTokenTest, NoAmr) {
  EXPECT_EQ(check([](json *p) { p->erase("amr"); }),
            "amr lacks required method fido");
}

TEST(IdTokenTest, AmrWithoutPasskey) {
  EXPECT_EQ(check([](json *p) { (*p)["amr"] = {"pwd", "mfa"}; }),
            "amr lacks required method fido");
}

TEST(IdTokenTest, NoOid) {
  EXPECT_EQ(check([](json *p) { p->erase("oid"); }),
            "missing or mistyped claim");
}

TEST(IdTokenTest, MistypedClaim) {
  EXPECT_EQ(check([](json *p) { (*p)["auth_time"] = "now"; }),
            "missing or mistyped claim");
}

TEST(IdTokenTest, AuthTimeAboveInt64) {
  EXPECT_EQ(check([](json *p) {
              (*p)["auth_time"] = json::parse("9223372036854775808");
            }),
            "missing or mistyped claim");
}

TEST(IdTokenTest, AuthTimeMinimum) {
  EXPECT_EQ(check([](json *p) {
              (*p)["auth_time"] = std::numeric_limits<int64_t>::min();
            }),
            "invalid auth_time");
}

TEST(IdTokenTest, AuthTimeFloat) {
  EXPECT_EQ(check([](json *p) { (*p)["auth_time"] = -1e300; }),
            "missing or mistyped claim");
}

TEST(IdTokenTest, ExpMinimum) {
  EXPECT_EQ(
      check([](json *p) { (*p)["exp"] = std::numeric_limits<int64_t>::min(); }),
      "id_token expired");
}

TEST(IdTokenTest, ExpMaximum) {
  EXPECT_EQ(
      check([](json *p) { (*p)["exp"] = std::numeric_limits<int64_t>::max(); }),
      "");
}

TEST(IdTokenTest, OidNotGuid) {
  EXPECT_EQ(check([](json *p) { (*p)["oid"] = "alice\n"; }),
            "oid is not an object ID");
}

TEST(IdTokenTest, Malformed) {
  std::string oid, reason;
  EXPECT_FALSE(validate_id_token("no-dots", config(), kNow, &oid, &reason));
  EXPECT_EQ(reason, "malformed id_token");
  EXPECT_FALSE(validate_id_token("a.!!!.c", config(), kNow, &oid, &reason));
  EXPECT_EQ(reason, "unreadable id_token payload");
}

TEST(AuthorizationTest, IsMapped) {
  EXPECT_TRUE(is_mapped(config(), "alice"));
  EXPECT_FALSE(is_mapped(config(), "mallory"));
}

TEST(AuthorizationTest, Mapping) {
  EXPECT_TRUE(is_authorized(config(), kOid, "alice"));
  EXPECT_FALSE(is_authorized(config(), kOid, "root"));
  EXPECT_FALSE(is_authorized(config(), "other", "alice"));
}

TEST(PromptTest, StripsControlCharacters) {
  DeviceCode code;
  code.verification_uri = "https://login.microsoft.com/device";
  code.user_code = "QWERTY\x1b[2J";
  EXPECT_EQ(prompt_text("host1\n", code),
            "sudo on host1: sign in at https://login.microsoft.com/device "
            "with code QWERTY[2J\nWaiting for the sign-in...");
}

// Against mock_server.py.
TEST(DeviceFlowTest, RequestAndPoll) {
  DeviceCode code = request_device_code(config());
  EXPECT_EQ(code.device_code, "abc+def/ghi=");
  EXPECT_EQ(code.interval, 1);
  std::string id_token = poll_for_id_token(config(), code, 30);
  std::string oid, reason;
  EXPECT_TRUE(validate_id_token(id_token, config(),
                                static_cast<int64_t>(std::time(nullptr)), &oid,
                                &reason))
      << reason;
  EXPECT_EQ(oid, kOid);
}

// The helper runs with an empty environment, so a dead proxy in ours
// changes nothing.
TEST(DeviceFlowTest, IgnoresProxyEnvironment) {
  setenv("http_proxy", "http://127.0.0.1:9", 1);
  setenv("ALL_PROXY", "http://127.0.0.1:9", 1);
  DeviceCode code = request_device_code(config());
  unsetenv("http_proxy");
  unsetenv("ALL_PROXY");
  EXPECT_EQ(code.device_code, "abc+def/ghi=");
}

TEST(DeviceFlowTest, RequestTooLarge) {
  EXPECT_THROW(post_form(std::string(ENTRA_AUTHORITY) + "/x",
                         std::string(kMaxRequest + 1, 'a')),
               std::runtime_error);
}

TEST(DeviceFlowTest, OversizedResponse) {
  Config c = config();
  c.tenant_id = "99999999-0000-0000-0000-000000000001";
  EXPECT_THROW(request_device_code(c), std::runtime_error);
}

TEST(DeviceFlowTest, IntervalClamped) {
  Config c = config();
  c.tenant_id = "99999999-0000-0000-0000-000000000002";
  EXPECT_EQ(request_device_code(c).interval, 30);
}

TEST(DeviceFlowTest, Declined) {
  DeviceCode code;
  code.device_code = "x-declined";
  code.interval = 1;
  code.expires_in = 30;
  EXPECT_THROW(poll_for_id_token(config(), code, 30), std::runtime_error);
}

TEST(DeviceFlowTest, Interrupted) {
  DeviceCode code;
  code.device_code = "abc+def/ghi=";
  code.interval = 1;
  code.expires_in = 30;
  StopSignals stop;
  raise(SIGINT);
  EXPECT_TRUE(stop_requested());
  EXPECT_THROW(poll_for_id_token(config(), code, 30), Interrupted);
}

TEST(DeviceFlowTest, StopSignalConsumed) {
  { StopSignals stop; }
  // The SIGINT raised in the previous test was consumed, not delivered.
  EXPECT_FALSE(stop_requested());
}

TEST(DeviceFlowTest, TransientFailureTolerated) {
  DeviceCode code;
  code.device_code = "x-flaky";
  code.interval = 1;
  code.expires_in = 30;
  EXPECT_FALSE(poll_for_id_token(config(), code, 30).empty());
}

TEST(DeviceFlowTest, PersistentFailure) {
  DeviceCode code;
  code.device_code = "x-broken";
  code.interval = 1;
  code.expires_in = 30;
  EXPECT_THROW(poll_for_id_token(config(), code, 30), std::exception);
}

TEST(DeviceFlowTest, Timeout) {
  DeviceCode code;
  code.device_code = "abc+def/ghi=";
  code.interval = 1;
  code.expires_in = 30;
  // A zero timeout must give up without polling.
  EXPECT_THROW(poll_for_id_token(config(), code, 0), std::runtime_error);
}

}  // namespace
