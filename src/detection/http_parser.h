#pragma once

#include <optional>
#include <string>

namespace minisnort::detection {

class HttpParser {
 public:
  std::optional<std::string> extract_uri(const std::string& payload) const;
};

}  // namespace minisnort::detection
