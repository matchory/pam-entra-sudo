#ifndef SRC_CONFIG_HPP_
#define SRC_CONFIG_HPP_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

// Loaded from the JSON file named in the PAM line. load() throws on any
// missing or invalid field, so a broken config denies sudo instead of
// weakening a check.
class Config {
 public:
  void load(const std::string &path);

  std::string tenant_id, client_id;
  // Longest accepted gap, in seconds, between the user's sign-in and now.
  int64_t max_auth_age = 0;
  // Every method listed must appear in the ID token's amr claim.
  std::vector<std::string> required_amr;
  // Entra object ID (oid) -> local accounts that object ID may sudo as.
  std::map<std::string, std::set<std::string>> users;
};

// True for a lowercase GUID such as an Entra tenant, client or object ID.
bool is_guid(const std::string &value);

#endif  // SRC_CONFIG_HPP_
