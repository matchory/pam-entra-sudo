// pam-entra-sudo-fetch: POSTs a form to one URL and prints the response body.
//
//   pam-entra-sudo-fetch URL < body
//
// The PAM module runs this instead of calling libcurl itself, so that HTTP and
// TLS happen in a fresh process: started with an empty environment and as an
// unprivileged user. Inside sudo, libcurl would otherwise read the invoking
// user's environment (SSLKEYLOGFILE, *_proxy) while running as root.
//
// Exit status: 0 with the body on stdout, 1 on a failed transfer, 2 on misuse.

#include <curl/curl.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <iterator>
#include <string>

#include "pam_entra_sudo.hpp"

namespace {

size_t append(void *data, size_t size, size_t nmemb, void *out) {
  auto *response = static_cast<std::string *>(out);
  size_t bytes = size * nmemb;
  if (response->size() + bytes > kMaxResponse) {
    return 0;  // makes curl fail the transfer with CURLE_WRITE_ERROR
  }
  response->append(static_cast<char *>(data), bytes);
  return bytes;
}

// Only the authority's own scheme: https in production, http for the mock
// server in tests.
bool https_only() {
  return std::string(ENTRA_AUTHORITY).rfind("https://", 0) == 0;
}

bool set(CURL *curl, CURLoption option, long value) {  // NOLINT
  return curl_easy_setopt(curl, option, value) == CURLE_OK;
}

bool set(CURL *curl, CURLoption option, const char *value) {
  return curl_easy_setopt(curl, option, value) == CURLE_OK;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2 || getuid() == 0) {
    return 2;
  }
  const std::string url = argv[1];
  if (url.rfind(std::string(ENTRA_AUTHORITY) + "/", 0) != 0) {
    return 2;
  }
  std::string body((std::istreambuf_iterator<char>(std::cin)),
                   std::istreambuf_iterator<char>());
  if (body.size() > kMaxRequest) {
    return 2;
  }

  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    return 1;
  }
  CURL *curl = curl_easy_init();
  if (curl == nullptr) {
    return 1;
  }
  std::string response;
  bool ok = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append) == CURLE_OK &&
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response) == CURLE_OK &&
            set(curl, CURLOPT_URL, url.c_str()) &&
            set(curl, CURLOPT_POSTFIELDS, body.c_str()) &&
#if LIBCURL_VERSION_NUM >= 0x075500  // 7.85.0
            set(curl, CURLOPT_PROTOCOLS_STR, https_only() ? "https" : "http") &&
#else
            set(curl, CURLOPT_PROTOCOLS,
                static_cast<long>(https_only() ? CURLPROTO_HTTPS  // NOLINT
                                               : CURLPROTO_HTTP)) &&
#endif
            // libcurl's defaults, stated so that no build loosens them.
            set(curl, CURLOPT_SSL_VERIFYPEER, 1L) &&
            set(curl, CURLOPT_SSL_VERIFYHOST, 2L) &&
            set(curl, CURLOPT_FOLLOWLOCATION, 0L) &&
            set(curl, CURLOPT_SSLVERSION,
                static_cast<long>(CURL_SSLVERSION_TLSv1_2)) &&  // NOLINT
            set(curl, CURLOPT_PROXY, "") &&
            set(curl, CURLOPT_CAINFO, ENTRA_CA_BUNDLE) &&
            set(curl, CURLOPT_CONNECTTIMEOUT, 10L) &&
            set(curl, CURLOPT_TIMEOUT, kRequestTimeout) &&
            set(curl, CURLOPT_NOSIGNAL, 1L) &&
            curl_easy_perform(curl) == CURLE_OK;
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  if (!ok) {
    return 1;
  }
  std::cout << response;
  std::cout.flush();
  return std::cout.good() ? 0 : 1;
}
