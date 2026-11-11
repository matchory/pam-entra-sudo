#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.hpp"
#include "gtest/gtest.h"

namespace {

const char kValid[] = R"({
  "tenant_id": "11111111-2222-3333-4444-555555555555",
  "client_id": "66666666-7777-8888-9999-000000000000",
  "max_auth_age": 120,
  "required_amr": ["fido"],
  "users": {"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": ["alice", "bob"]}
})";

// Writes `content` to a temporary file and loads it.
void load(Config *config, const std::string &content) {
  const char path[] = "test_config.tmp.json";
  {
    std::ofstream out(path);
    out << content;
  }
  try {
    config->load(path);
  } catch (...) {
    std::remove(path);
    throw;
  }
  std::remove(path);
}

std::string replace(std::string s, const std::string &from,
                    const std::string &to) {
  size_t pos = s.find(from);
  if (pos == std::string::npos) {
    throw std::logic_error("test fixture lacks " + from);
  }
  return s.replace(pos, from.size(), to);
}

TEST(ConfigTest, Valid) {
  Config config;
  load(&config, kValid);
  EXPECT_EQ(config.tenant_id, "11111111-2222-3333-4444-555555555555");
  EXPECT_EQ(config.max_auth_age, 120);
  EXPECT_EQ(config.required_amr, std::vector<std::string>{"fido"});
  EXPECT_EQ(config.users["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"].count("bob"),
            1u);
}

TEST(ConfigTest, MissingFile) {
  Config config;
  EXPECT_THROW(config.load("does-not-exist.json"), std::exception);
}

TEST(ConfigTest, NotJson) {
  Config config;
  EXPECT_THROW(load(&config, "{"), std::exception);
}

TEST(ConfigTest, MissingField) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "\"max_auth_age\": 120,", "")),
               std::exception);
}

TEST(ConfigTest, TenantNotGuid) {
  Config config;
  EXPECT_THROW(
      load(&config, replace(kValid, "11111111-2222-3333-4444-555555555555",
                            "evil.example/x")),
      std::exception);
}

TEST(ConfigTest, ClientNotGuid) {
  Config config;
  EXPECT_THROW(
      load(&config, replace(kValid, "66666666-7777-8888-9999-000000000000",
                            "client&scope=x")),
      std::exception);
}

TEST(ConfigTest, MaxAuthAgeNotPositive) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "120", "0")), std::exception);
}

TEST(ConfigTest, RequiredAmrEmpty) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "[\"fido\"]", "[]")),
               std::exception);
}

TEST(ConfigTest, UsersEmpty) {
  Config config;
  EXPECT_THROW(
      load(&config, replace(kValid,
                            "{\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\": "
                            "[\"alice\", \"bob\"]}",
                            "{}")),
      std::exception);
}

TEST(ConfigTest, UserKeyNotObjectId) {
  Config config;
  EXPECT_THROW(
      load(&config, replace(kValid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                            "alice@example.com")),
      std::exception);
}

TEST(ConfigTest, MapsToRoot) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "\"bob\"", "\"root\"")),
               std::exception);
}

TEST(ConfigTest, MaxAuthAgeNotInteger) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "120", "120.5")), std::exception);
}

TEST(ConfigTest, MaxAuthAgeTooLarge) {
  Config config;
  EXPECT_THROW(load(&config, replace(kValid, "120", "3601")), std::exception);
}

TEST(ConfigTest, Symlink) {
  const char target[] = "test_config.target.json";
  const char link[] = "test_config.link.json";
  {
    std::ofstream out(target);
    out << kValid;
  }
  std::remove(link);
  ASSERT_EQ(symlink(target, link), 0);
  Config config;
  EXPECT_THROW(config.load(link), std::exception);
  std::remove(link);
  std::remove(target);
}

TEST(ConfigTest, Guid) {
  EXPECT_TRUE(is_guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
  EXPECT_FALSE(is_guid("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"));
  EXPECT_FALSE(is_guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"));
}

}  // namespace
