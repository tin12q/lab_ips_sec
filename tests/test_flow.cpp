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

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpAck = 0x10;

rules::Rule make_rule(uint32_t sid) {
  rules::Rule rule;
  rule.action = rules::Action::kDrop;
  rule.proto = rules::Proto::kTcp;
  rule.dst_port = "80";
  rule.sid = sid;
  return rule;
}

core::Packet make_tcp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                             uint8_t flags, const std::string& payload = "") {
  core::Packet packet{};
  packet.is_ipv4 = true;
  packet.is_tcp = true;
  packet.src_ip = src_ip;
  packet.dst_ip = dst_ip;
  packet.src_port = src_port;
  packet.dst_port = dst_port;
  packet.tcp_flags = flags;
  packet.payload = reinterpret_cast<const uint8_t*>(payload.data());
  packet.payload_len = payload.size();
  return packet;
}

}  // namespace

TEST_CASE("engine flow_to_server uses client-origin direction", "[flow][engine]") {
  auto rule = make_rule(4000001);
  rule.flow_to_server = true;

  rules::RuleStore store;
  store.set_rules({rule});
  Engine engine(store);

  const auto client_to_server = make_tcp_packet(0x0A000001, 0x0A000002, 12345, 80, kTcpSyn,
                                                 "GET / HTTP/1.1\r\n\r\n");
  const auto server_to_client = make_tcp_packet(0x0A000002, 0x0A000001, 80, 12345, kTcpAck,
                                                 "HTTP/1.1 200 OK\r\n\r\n");

  const auto client_decision = engine.inspect(client_to_server);
  REQUIRE(client_decision.verdict == Verdict::kDrop);
  REQUIRE(client_decision.matched_sids == std::vector<uint32_t>{4000001});

  const auto server_decision = engine.inspect(server_to_client);
  REQUIRE(server_decision.verdict == Verdict::kAccept);
  REQUIRE(server_decision.matched_sids.empty());
}

TEST_CASE("engine flow_established requires handshake completion", "[flow][engine]") {
  auto rule = make_rule(4000002);
  rule.flow_to_server = true;
  rule.flow_established = true;

  rules::RuleStore store;
  store.set_rules({rule});
  Engine engine(store);

  const auto syn = make_tcp_packet(0x0A000001, 0x0A000002, 22222, 80, kTcpSyn, "pre");
  const auto syn_ack = make_tcp_packet(0x0A000002, 0x0A000001, 80, 22222, static_cast<uint8_t>(kTcpSyn | kTcpAck));
  const auto ack = make_tcp_packet(0x0A000001, 0x0A000002, 22222, 80, kTcpAck, "post");

  REQUIRE(engine.inspect(syn).verdict == Verdict::kAccept);
  REQUIRE(engine.inspect(syn_ack).verdict == Verdict::kAccept);

  const auto decision = engine.inspect(ack);
  REQUIRE(decision.verdict == Verdict::kDrop);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{4000002});
}

TEST_CASE("engine keeps pass precedence with flow-filtered candidates", "[flow][engine]") {
  auto drop_rule = make_rule(4000003);
  drop_rule.flow_to_server = true;

  auto pass_rule = make_rule(4000004);
  pass_rule.action = rules::Action::kPass;
  pass_rule.flow_to_server = true;

  rules::RuleStore store;
  store.set_rules({drop_rule, pass_rule});
  Engine engine(store);

  const auto packet = make_tcp_packet(0x0A000001, 0x0A000002, 34567, 80, kTcpSyn, "GET /admin HTTP/1.1\r\n\r\n");
  const auto decision = engine.inspect(packet);

  REQUIRE(decision.verdict == Verdict::kAccept);
  REQUIRE(decision.matched_sids == std::vector<uint32_t>{4000004});
}

TEST_CASE("engine drops rule match before flow closes and ignores after close", "[flow][engine]") {
  auto rule = make_rule(4000005);
  rule.flow_to_server = true;

  rules::RuleStore store;
  store.set_rules({rule});
  Engine engine(store);

  const auto syn = make_tcp_packet(0x0A000011, 0x0A000012, 45678, 80, kTcpSyn, "GET /a HTTP/1.1\r\n\r\n");
  const auto fin = make_tcp_packet(0x0A000011, 0x0A000012, 45678, 80, kTcpFin, "GET /b HTTP/1.1\r\n\r\n");
  const auto after_fin_reverse =
      make_tcp_packet(0x0A000012, 0x0A000011, 80, 45678, kTcpAck, "HTTP/1.1 200 OK\r\n\r\n");

  REQUIRE(engine.inspect(syn).verdict == Verdict::kDrop);
  REQUIRE(engine.inspect(fin).verdict == Verdict::kDrop);

  const auto after_close = engine.inspect(after_fin_reverse);
  REQUIRE(after_close.verdict == Verdict::kAccept);
}

}  // namespace minisnort::detection
