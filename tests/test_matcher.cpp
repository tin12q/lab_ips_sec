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
  rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kPayload});

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

TEST_CASE("matcher applies http_uri content to normalized and decoded uri", "[matcher]") {
  Matcher matcher;

  rules::Rule admin_rule;
  admin_rule.proto = rules::Proto::kTcp;
  admin_rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto admin_packet = make_packet_from_literal("GET /foo/%2e%2e/admin HTTP/1.1\r\nHost: victim\r\n\r\n");
  admin_packet.is_tcp = true;
  REQUIRE(matcher.match(admin_rule, admin_packet));

  rules::Rule traversal_rule;
  traversal_rule.proto = rules::Proto::kTcp;
  traversal_rule.contents.push_back(rules::ContentOpt{"../", false, rules::HttpBuffer::kUri});
  REQUIRE(matcher.match(traversal_rule, admin_packet));

  auto body_only_packet = make_packet_from_literal("GET /index HTTP/1.1\r\n\r\n/admin");
  body_only_packet.is_tcp = true;
  REQUIRE_FALSE(matcher.match(admin_rule, body_only_packet));
}

TEST_CASE("matcher fails http_uri content for malformed request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto packet = make_packet_from_literal("not-http /admin");
  packet.is_tcp = true;

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher rejects uppercase non-http request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto packet = make_packet_from_literal("FOO /admin BAR");
  packet.is_tcp = true;

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher supports lf-only request line", "[matcher]") {
  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto packet = make_packet_from_literal("GET /admin HTTP/1.1\nHost: victim\n\n");
  packet.is_tcp = true;

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher matches Sprint 7 HTTP header method and body buffers", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\n"
      "Host: victim\r\n"
      "User-Agent: sqlmap/1.7\r\n"
      "Content-Length: 22\r\n"
      "\r\n"
      "id=1 UNION SELECT user";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;

  rules::Rule header_rule;
  header_rule.proto = rules::Proto::kTcp;
  header_rule.contents.push_back(rules::ContentOpt{"sqlmap", true, rules::HttpBuffer::kHeader});
  REQUIRE(matcher.match(header_rule, packet));

  rules::Rule method_rule;
  method_rule.proto = rules::Proto::kTcp;
  method_rule.contents.push_back(rules::ContentOpt{"POST", false, rules::HttpBuffer::kMethod});
  REQUIRE(matcher.match(method_rule, packet));

  rules::Rule body_rule;
  body_rule.proto = rules::Proto::kTcp;
  body_rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kClientBody});
  REQUIRE(matcher.match(body_rule, packet));
}

TEST_CASE("matcher handles two pipelined HTTP requests", "[matcher]") {
  const std::string payload =
      "GET /index HTTP/1.1\r\nHost: victim\r\n\r\n"
      "GET /admin HTTP/1.1\r\nHost: victim\r\n\r\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher keeps HTTP contents scoped to one pipelined request", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\n\r\nsafe"
      "GET /index HTTP/1.1\r\nHost: evil.example\r\n\r\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"evil.example", false, rules::HttpBuffer::kHeader});
  rule.contents.push_back(rules::ContentOpt{"safe", false, rules::HttpBuffer::kClientBody});

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher applies pcre to HTTP body when rule has body content", "[matcher]") {
  const std::string payload =
      "POST /login?debug=union%20select HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Content-Length: 10\r\n"
      "\r\n"
      "UNION noop";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"UNION", true, rules::HttpBuffer::kClientBody});
  rule.pcre = rules::PcreOpt{"/union\\s+select/i", false, rules::HttpBuffer::kClientBody};

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher scopes body-only pcre to HTTP body", "[matcher]") {
  const std::string payload =
      "POST /login?debug=union%20select HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Content-Length: 10\r\n"
      "\r\n"
      "UNION noop";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.pcre = rules::PcreOpt{"/union\\s+select/i", false, rules::HttpBuffer::kClientBody};

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher keeps unscoped pcre payload-wide with HTTP content", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Content-Length: 10\r\n"
      "\r\n"
      "UNION noop";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"POST", false, rules::HttpBuffer::kMethod});
  rule.pcre = rules::PcreOpt{"/Host:\\s+victim/i", false};

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher scopes mixed content and pcre to body", "[matcher]") {
  const std::string payload =
      "POST /login?debug=union%20select HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Content-Length: 22\r\n"
      "\r\n"
      "id=1 UNION SELECT user";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"UNION", true, rules::HttpBuffer::kClientBody});
  rule.pcre = rules::PcreOpt{"/union\\s+select/i", false, rules::HttpBuffer::kClientBody};

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher inspects chunked HTTP body", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "16\r\n"
      "id=1 UNION SELECT user\r\n"
      "0\r\n"
      "\r\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kClientBody});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher inspects chunked HTTP body with trailer headers", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "16\r\n"
      "id=1 UNION SELECT user\r\n"
      "0\r\n"
      "X-Trailer: y\r\n"
      "\r\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kClientBody});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher inspects LF-only HTTP body", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\n"
      "Host: victim\n"
      "Content-Length: 22\n"
      "\n"
      "id=1 UNION SELECT user";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kClientBody});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher inspects LF-only chunked HTTP body", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\n"
      "Host: victim\n"
      "Transfer-Encoding: chunked\n"
      "\n"
      "16\n"
      "id=1 UNION SELECT user\n"
      "0\n"
      "\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"union select", true, rules::HttpBuffer::kClientBody});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher rejects oversized content length without wrapping", "[matcher]") {
  const std::string payload =
      "POST /login HTTP/1.1\r\n"
      "Host: victim\r\n"
      "Content-Length: 18446744073709551615\r\n"
      "\r\n";

  auto packet = make_packet(payload);
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"anything", false, rules::HttpBuffer::kClientBody});

  REQUIRE_FALSE(matcher.match(rule, packet));
}

TEST_CASE("matcher detects over-encoded traversal", "[matcher]") {
  auto packet = make_packet_from_literal("GET /foo/%25252e%25252e%25252fadmin HTTP/1.1\r\nHost: victim\r\n\r\n");
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"../", false, rules::HttpBuffer::kUri});

  REQUIRE(matcher.match(rule, packet));
}

TEST_CASE("matcher detects backslash traversal", "[matcher]") {
  auto packet = make_packet_from_literal("GET /foo/%255c..%255cadmin HTTP/1.1\r\nHost: victim\r\n\r\n");
  packet.is_tcp = true;

  Matcher matcher;
  rules::Rule rule;
  rule.proto = rules::Proto::kTcp;
  rule.contents.push_back(rules::ContentOpt{"../", false, rules::HttpBuffer::kUri});

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
