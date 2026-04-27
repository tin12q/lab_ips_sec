#pragma once

#include <optional>
#include <string>
#include <vector>

namespace minisnort::detection {

struct HttpBuffers {
  std::string method;
  std::string uri;
  std::string decoded_uri;
  std::string headers;
  std::string client_body;
};

class HttpParser {
 public:
  std::optional<std::string> extract_uri(const std::string& payload) const;
  std::vector<HttpBuffers> parse_requests(const std::string& payload) const;
};

}  // namespace minisnort::detection
