#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/packet.h"
#include "detection/matcher.h"
#include "rules/rule.h"

namespace minisnort::detection {
namespace {

core::Packet make_packet(const std::string& payload) {
  core::Packet packet{};
  packet.raw = nullptr;
  packet.raw_len = 0;
  packet.payload = reinterpret_cast<const uint8_t*>(payload.data());
  packet.payload_len = payload.size();
  packet.is_ipv4 = true;
  return packet;
}

core::Packet make_packet_from_literal(const char* payload) {
  static std::string stable_payload;
  stable_payload = payload;
  return make_packet(stable_payload);
}

}  // namespace

TEST_CASE("matcher matches icmp type", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kIcmp;
  rule.icmp_type = 8;

  auto packet = make_packet("");
  packet.is_icmp = true;
  packet.icmp_type = 8;

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher checks tcp flags", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.tcp_flags_required = 0x12;

  auto packet = make_packet_from_literal("GET / HTTP/1.1");
  packet.is_tcp = true;
  packet.tcp_flags = 0x12;

  REQUIRE(matcher.match(rule, packet));

  packet.tcp_flags = 0x10;
  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher checks content and nocase", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"union select", true, false});

  auto packet = make_packet_from_literal("GET /?q=UNION SELECT user HTTP/1.1");
  packet.is_tcp = true;

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher checks pcre", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.pcre = rules::PcreOpt{"/union\\s+select/i", false};

  auto packet = make_packet_from_literal("GET /?q=UNION SELECT user HTTP/1.1");
  packet.is_tcp = true;

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher applies http_uri content to uri only", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, true});

  auto admin_packet = make_packet_from_literal("GET /admin HTTP/1.1\r\nHost: victim\r\n\r\n");
  admin_packet.is_tcp = true;
  REQUIRE(matcher.match(rule, admin_packet));

  auto body_only_packet = make_packet_from_literal("GET /index HTTP/1.1\r\n\r\n/admin");
  body_only_packet.is_tcp = true;
  REQUIRE_FALSE(matcher.match(rule, body_only_packet));
}

TEST_CASE("matcher fails http_uri content for malformed request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, true});

  auto packet = make_packet_from_literal("not-http /admin");
  packet.is_tcp = true;

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher rejects uppercase non-http request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, true});

  auto packet = make_packet_from_literal("FOO /admin BAR");
  packet.is_tcp = true;

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher supports lf-only request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, true});

  auto packet = make_packet_from_literal("GET /admin HTTP/1.1\nHost: victim\n\n");
  packet.is_tcp = true;

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher returns false for invalid regex", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.pcre = rules::PcreOpt{"/[a-/", false};

  auto packet = make_packet_from_literal("GET / HTTP/1.1");
  packet.is_tcp = true;

  REQUIRE_FALSE(matcher.match(rule, packet));
}

}  // namespace minisnort::detection
