#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "core/packet.h"
#include "detection/engine.h"
#include "rules/rule.h"
#include "rules/rule_store.h"

namespace minisnort::detection {
namespace {

core::Packet make_tcp_packet(const std::string& payload, uint16_t dst_port,
                             uint32_t src_ip = 0x0A000001, uint32_t dst_ip = 0x0A000002,
                             uint64_t timestamp_us = 0) {
  core::Packet packet{};
  packet.payload = reinterpret_cast<const uint8_t*>(payload.data());
  packet.payload_len = payload.size();
  packet.is_ipv4 = true;
  packet.is_tcp = true;
  packet.src_ip = src_ip;
  packet.dst_ip = dst_ip;
  packet.dst_port = dst_port;
  packet.timestamp_us = timestamp_us;
  return packet;
}

core::Packet make_icmp_packet(uint8_t icmp_type) {
  core::Packet packet{};
  packet.is_ipv4 = true;
  packet.is_icmp = true;
  packet.icmp_type = icmp_type;
  packet.dst_port = 0;
  return packet;
}

rules::Rule make_rule(rules::Action action, rules::Proto proto, const std::string& dst_port,
                      uint32_t sid) {
  rules::Rule rule;
  rule.action = action;
  rule.proto = proto;
  rule.dst_port = dst_port;
  rule.sid = sid;
  return rule;
}

}  // namespace

TEST_CASE("engine drops when drop rule matches", "[engine]") {
  auto drop_rule = make_rule(rules::Action::kDrop, rules::Proto::kIcmp, "any", 1000005);
  drop_rule.icmp_type = 8;

  rules::RuleStore store;
  store.set_rules({drop_rule});

  Engine engine(store);
  const auto packet = make_icmp_packet(8);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kDrop);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{1000005});
}

TEST_CASE("engine accepts when no rule matches", "[engine]") {
  auto rule = make_rule(rules::Action::kDrop, rules::Proto::kTcp, "80", 1000006);
  rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  rules::RuleStore store;
  store.set_rules({rule});

  Engine engine(store);
  const std::string payload = "GET /index HTTP/1.1\r\n\r\n";
  const auto packet = make_tcp_packet(payload, 80);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kAccept);
  REQUIRE(decision.matched_sids.empty());
}

TEST_CASE("engine prefers pass over drop", "[engine]") {
  auto pass_rule = make_rule(rules::Action::kPass, rules::Proto::kTcp, "80", 2000001);
  pass_rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto drop_rule = make_rule(rules::Action::kDrop, rules::Proto::kTcp, "80", 2000002);
  drop_rule.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  rules::RuleStore store;
  store.set_rules({drop_rule, pass_rule});

  Engine engine(store);
  const std::string payload = "GET /admin HTTP/1.1\r\n\r\n";
  const auto packet = make_tcp_packet(payload, 80);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kAccept);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{2000001});
}

TEST_CASE("engine records alert sid while keeping accept verdict", "[engine]") {
  auto alert_rule = make_rule(rules::Action::kAlert, rules::Proto::kIcmp, "any", 1000001);
  alert_rule.icmp_type = 8;

  rules::RuleStore store;
  store.set_rules({alert_rule});

  Engine engine(store);
  const auto packet = make_icmp_packet(8);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kAccept);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{1000001});
}

TEST_CASE("engine evaluates ip drop rules for tcp packets", "[engine]") {
  auto ip_drop = make_rule(rules::Action::kDrop, rules::Proto::kIp, "any", 3000001);
  ip_drop.contents.push_back(rules::ContentOpt{"blocked", true, rules::HttpBuffer::kPayload});

  rules::RuleStore store;
  store.set_rules({ip_drop});

  Engine engine(store);
  const std::string payload = "GET /blocked HTTP/1.1\r\n\r\n";
  const auto packet = make_tcp_packet(payload, 80);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kDrop);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{3000001});
}

TEST_CASE("engine pass rule on ip overrides tcp drop", "[engine]") {
  auto tcp_drop = make_rule(rules::Action::kDrop, rules::Proto::kTcp, "80", 3000002);
  tcp_drop.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  auto ip_pass = make_rule(rules::Action::kPass, rules::Proto::kIp, "any", 3000003);
  ip_pass.contents.push_back(rules::ContentOpt{"/admin", false, rules::HttpBuffer::kUri});

  rules::RuleStore store;
  store.set_rules({tcp_drop, ip_pass});

  Engine engine(store);
  const std::string payload = "GET /admin HTTP/1.1\r\n\r\n";
  const auto packet = make_tcp_packet(payload, 80);

  const auto decision = engine.inspect(packet);
  REQUIRE(decision.verdict == Verdict::kAccept);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{3000003});
}

}  // namespace minisnort::detection
