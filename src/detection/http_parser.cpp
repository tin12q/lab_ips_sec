#include "detection/http_parser.h"

#include <cctype>

namespace minisnort::detection {

std::optional<std::string> HttpParser::extract_uri(const std::string& payload) const {
  size_t line_end = payload.find("\r\n");
  if (line_end == std::string::npos) {
    line_end = payload.find('\n');
  }
  const std::string request_line = line_end == std::string::npos ? payload : payload.substr(0, line_end);

  const size_t method_end = request_line.find(' ');
  if (method_end == std::string::npos || method_end == 0) {
    return std::nullopt;
  }

  const size_t uri_end = request_line.find(' ', method_end + 1);
  if (uri_end == std::string::npos || uri_end <= method_end + 1) {
    return std::nullopt;
  }

  if (request_line.find(' ', uri_end + 1) != std::string::npos) {
    return std::nullopt;
  }

  const std::string method = request_line.substr(0, method_end);
  for (char c : method) {
    if (!std::isupper(static_cast<unsigned char>(c))) {
      return std::nullopt;
    }
  }

  const std::string version = request_line.substr(uri_end + 1);
  if (version.rfind("HTTP/", 0) != 0) {
    return std::nullopt;
  }

  const std::string uri = request_line.substr(method_end + 1, uri_end - (method_end + 1));
  if (uri.empty()) {
    return std::nullopt;
  }
  for (char c : uri) {
    if (std::iscntrl(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c))) {
      return std::nullopt;
    }
  }

  return uri;
}

}  // namespace minisnort::detection
