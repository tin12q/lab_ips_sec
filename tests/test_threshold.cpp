#include <cstdint>

#include <catch2/catch_test_macros.hpp>

#include "core/packet.h"
#include "detection/threshold.h"
#include "rules/rule.h"

namespace minisnort::detection {
namespace {

rules::Rule make_threshold_rule(uint32_t sid, rules::ThresholdOpt::Track track, int count, int seconds) {
  rules::Rule rule;
  rule.sid = sid;
  rule.threshold = rules::ThresholdOpt{track, count, seconds};
  return rule;
}

core::Packet make_packet(uint32_t src_ip, uint32_t dst_ip, uint64_t timestamp_us) {
  core::Packet packet{};
  packet.src_ip = src_ip;
  packet.dst_ip = dst_ip;
  packet.timestamp_us = timestamp_us;
  return packet;
}

}  // namespace

TEST_CASE("threshold allows rule immediately when threshold is absent", "[threshold]") {
  Threshold threshold;
  rules::Rule rule;
  rule.sid = 1;

  const auto packet = make_packet(0x0A000001, 0x0A000002, 1000);
  REQUIRE(threshold.allow(rule, packet));
}

TEST_CASE("threshold triggers exactly at count within sliding window", "[threshold]") {
  Threshold threshold;
  const auto rule = make_threshold_rule(1000002, rules::ThresholdOpt::Track::kBySrc, 3, 5);

  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 0)));
  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 2'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 4'999'999)));
}

TEST_CASE("threshold evicts events at window boundary", "[threshold]") {
  Threshold threshold;
  const auto rule = make_threshold_rule(1000002, rules::ThresholdOpt::Track::kBySrc, 2, 5);

  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 0)));
  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 5'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 9'999'999)));
}

TEST_CASE("threshold tracks counters independently by source", "[threshold]") {
  Threshold threshold;
  const auto rule = make_threshold_rule(1000003, rules::ThresholdOpt::Track::kBySrc, 2, 10);

  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000A, 0)));
  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000002, 0x0A00000A, 1'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000A, 2'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000002, 0x0A00000A, 3'000'000)));
}

TEST_CASE("threshold tracks counters independently by destination", "[threshold]") {
  Threshold threshold;
  const auto rule = make_threshold_rule(1000004, rules::ThresholdOpt::Track::kByDst, 2, 10);

  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000A, 0)));
  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000B, 500'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000A, 1'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A00000B, 1'500'000)));
}

TEST_CASE("threshold resets bucket after trigger", "[threshold]") {
  Threshold threshold;
  const auto rule = make_threshold_rule(1000005, rules::ThresholdOpt::Track::kBySrc, 2, 10);

  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 0)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 1'000'000)));
  REQUIRE_FALSE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 2'000'000)));
  REQUIRE(threshold.allow(rule, make_packet(0x0A000001, 0x0A000002, 3'000'000)));
}

}  // namespace minisnort::detection
