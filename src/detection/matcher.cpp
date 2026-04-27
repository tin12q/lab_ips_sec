#include "detection/matcher.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>

namespace minisnort::detection {
namespace {

std::string payload_to_string(const core::Packet& packet) {
  if (packet.payload == nullptr || packet.payload_len == 0) {
    return "";
  }
  return std::string(reinterpret_cast<const char*>(packet.payload), packet.payload_len);
}

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool contains_with_case(const std::string& haystack, const std::string& needle, bool nocase) {
  if (!nocase) {
    return haystack.find(needle) != std::string::npos;
  }
  return to_lower(haystack).find(to_lower(needle)) != std::string::npos;
}

struct RegexPattern {
  std::string pattern;
  bool icase = false;
};

RegexPattern normalize_regex(const rules::PcreOpt& opt) {
  RegexPattern out{opt.regex, opt.nocase};
  if (out.pattern.size() >= 2 && out.pattern.front() == '/') {
    const auto close = out.pattern.find_last_of('/');
    if (close != std::string::npos && close > 0) {
      const std::string flags = out.pattern.substr(close + 1);
      out.pattern = out.pattern.substr(1, close - 1);
      if (flags.find('i') != std::string::npos) {
        out.icase = true;
      }
    }
  }
  return out;
}

}  // namespace

bool Matcher::match(const rules::Rule& rule, const core::Packet& packet) const {
  return match_proto(rule, packet) && match_icmp_type(rule, packet) && match_tcp_flags(rule, packet) &&
         match_contents(rule, packet) && match_pcre(rule, packet);
}

bool Matcher::match_proto(const rules::Rule& rule, const core::Packet& packet) const {
  switch (rule.proto) {
    case rules::Proto::kIp:
      return packet.is_ipv4;
    case rules::Proto::kTcp:
      return packet.is_tcp;
    case rules::Proto::kUdp:
      return packet.is_udp;
    case rules::Proto::kIcmp:
      return packet.is_icmp;
  }
  return false;
}

bool Matcher::match_icmp_type(const rules::Rule& rule, const core::Packet& packet) const {
  if (!rule.icmp_type.has_value()) {
    return true;
  }
  return packet.is_icmp && packet.icmp_type == rule.icmp_type.value();
}

bool Matcher::match_tcp_flags(const rules::Rule& rule, const core::Packet& packet) const {
  if (!rule.tcp_flags_required.has_value()) {
    return true;
  }
  if (!packet.is_tcp) {
    return false;
  }
  const uint8_t required = rule.tcp_flags_required.value();
  return (packet.tcp_flags & required) == required;
}

bool Matcher::match_contents(const rules::Rule& rule, const core::Packet& packet) const {
  if (rule.contents.empty()) {
    return true;
  }

  const std::string payload = payload_to_string(packet);
  const std::optional<std::string> uri = http_parser_.extract_uri(payload);

  for (const auto& content : rule.contents) {
    const std::string* haystack = &payload;
    if (content.http_uri) {
      if (!uri.has_value()) {
        return false;
      }
      haystack = &uri.value();
    }

    if (!contains_with_case(*haystack, content.pattern, content.nocase)) {
      return false;
    }
  }
  return true;
}

bool Matcher::match_pcre(const rules::Rule& rule, const core::Packet& packet) const {
  if (!rule.pcre.has_value()) {
    return true;
  }

  const RegexPattern normalized = normalize_regex(rule.pcre.value());
  std::regex_constants::syntax_option_type options = std::regex_constants::ECMAScript;
  if (normalized.icase) {
    options |= std::regex_constants::icase;
  }

  try {
    const std::regex re(normalized.pattern, options);
    const std::string payload = payload_to_string(packet);
    return std::regex_search(payload, re);
  } catch (const std::regex_error&) {
    return false;
  }
}

}  // namespace minisnort::detection
