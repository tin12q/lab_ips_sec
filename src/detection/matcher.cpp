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

struct HttpMatchContext {
  std::vector<HttpBuffers> requests;
  std::vector<size_t> matching_request_indexes;
  bool has_http_content = false;
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

const std::string& http_buffer_value(const HttpBuffers& request, rules::HttpBuffer buffer) {
  switch (buffer) {
    case rules::HttpBuffer::kHeader:
      return request.headers;
    case rules::HttpBuffer::kMethod:
      return request.method;
    case rules::HttpBuffer::kClientBody:
      return request.client_body;
    case rules::HttpBuffer::kUri:
    case rules::HttpBuffer::kPayload:
      return request.uri;
  }
  return request.uri;
}

bool http_content_matches(const HttpBuffers& request, const rules::ContentOpt& content) {
  if (content.http_buffer == rules::HttpBuffer::kUri) {
    return contains_with_case(request.uri, content.pattern, content.nocase) ||
           contains_with_case(request.decoded_uri, content.pattern, content.nocase);
  }
  return contains_with_case(http_buffer_value(request, content.http_buffer), content.pattern, content.nocase);
}

bool regex_matches(const RegexPattern& normalized, const std::string& haystack) {
  std::regex_constants::syntax_option_type options = std::regex_constants::ECMAScript;
  if (normalized.icase) {
    options |= std::regex_constants::icase;
  }

  const std::regex re(normalized.pattern, options);
  return std::regex_search(haystack, re);
}

}  // namespace

bool Matcher::match(const rules::Rule& rule, const core::Packet& packet) const {
  std::vector<size_t> matching_request_indexes;
  bool has_http_content = false;
  return match_proto(rule, packet) && match_icmp_type(rule, packet) && match_tcp_flags(rule, packet) &&
         match_contents(rule, packet, matching_request_indexes, has_http_content) &&
         match_pcre(rule, packet, matching_request_indexes, has_http_content);
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

bool Matcher::match_contents(const rules::Rule& rule, const core::Packet& packet,
                             std::vector<size_t>& matching_request_indexes, bool& has_http_content) const {
  if (rule.contents.empty()) {
    return true;
  }

  const std::string payload = payload_to_string(packet);
  const std::vector<HttpBuffers> requests = http_parser_.parse_requests(payload);
  std::vector<const rules::ContentOpt*> http_contents;

  for (const auto& content : rule.contents) {
    if (content.http_buffer == rules::HttpBuffer::kPayload) {
      if (!contains_with_case(payload, content.pattern, content.nocase)) {
        return false;
      }
    } else {
      http_contents.push_back(&content);
    }
  }

  if (http_contents.empty()) {
    return true;
  }

  has_http_content = true;
  for (size_t i = 0; i < requests.size(); ++i) {
    bool request_matches = true;
    for (const rules::ContentOpt* content : http_contents) {
      if (!http_content_matches(requests[i], *content)) {
        request_matches = false;
        break;
      }
    }
    if (request_matches) {
      matching_request_indexes.push_back(i);
    }
  }

  return !matching_request_indexes.empty();
}

bool Matcher::match_pcre(const rules::Rule& rule, const core::Packet& packet,
                         const std::vector<size_t>& matching_request_indexes, bool has_http_content) const {
  if (!rule.pcre.has_value()) {
    return true;
  }

  const RegexPattern normalized = normalize_regex(rule.pcre.value());

  try {
    if (!has_http_content && rule.pcre->http_buffer == rules::HttpBuffer::kPayload) {
      return regex_matches(normalized, payload_to_string(packet));
    }

    const std::vector<HttpBuffers> requests = http_parser_.parse_requests(payload_to_string(packet));
    if (!has_http_content) {
      for (const auto& request : requests) {
        if (regex_matches(normalized, http_buffer_value(request, rule.pcre->http_buffer))) {
          return true;
        }
      }
      return false;
    }

    for (size_t index : matching_request_indexes) {
      if (index >= requests.size()) {
        continue;
      }
      const std::string& haystack = rule.pcre->http_buffer == rules::HttpBuffer::kPayload
                                      ? payload_to_string(packet)
                                      : http_buffer_value(requests[index], rule.pcre->http_buffer);
      if (regex_matches(normalized, haystack)) {
        return true;
      }
    }
    return false;
  } catch (const std::regex_error&) {
    return false;
  }
}

}  // namespace minisnort::detection
