#pragma once

#include "core/packet.h"
#include "detection/http_parser.h"
#include "rules/rule.h"

namespace minisnort::detection {

class Matcher {
 public:
  bool match(const rules::Rule& rule, const core::Packet& packet) const;

 private:
  HttpParser http_parser_{};
  bool match_proto(const rules::Rule& rule, const core::Packet& packet) const;
  bool match_icmp_type(const rules::Rule& rule, const core::Packet& packet) const;
  bool match_tcp_flags(const rules::Rule& rule, const core::Packet& packet) const;
  bool match_contents(const rules::Rule& rule, const core::Packet& packet) const;
  bool match_pcre(const rules::Rule& rule, const core::Packet& packet) const;
};

}  // namespace minisnort::detection
