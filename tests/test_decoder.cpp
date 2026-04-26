#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "core/packet.h"
#include "decoder/decoder.h"

namespace {

std::vector<uint8_t> buildEthernetIpv4TcpPacket() {
  return {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x14,
      0x00, 0x0a, 0xac, 0x15, 0x00, 0x14, 0xd4, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x45,
      0x54, 0x20, 0x2f, 0x0a};
}

std::vector<uint8_t> buildEthernetIpv4UdpPacket() {
  return {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x20, 0x56, 0x78, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xac, 0x14,
      0x00, 0x0a, 0x08, 0x08, 0x08, 0x08, 0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00,
      0xde, 0xad, 0xbe, 0xef};
}

std::vector<uint8_t> buildEthernetIpv4IcmpPacket() {
  return {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x20, 0x11, 0x11, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xac, 0x14,
      0x00, 0x0a, 0xac, 0x15, 0x00, 0x14, 0x08, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
      0x01, 0x02, 0x03, 0x04};
}

std::vector<uint8_t> buildEthernetArpPacket() {
  return {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x06,
      0x00, 0x01, 0x08, 0x00};
}

}  // namespace

TEST_CASE("decode TCP packet and produce summary") {
  const auto bytes = buildEthernetIpv4TcpPacket();
  minisnort::core::Packet packet;

  const bool ok = minisnort::decoder::decodePacket(bytes.data(), bytes.size(), packet);

  REQUIRE(ok);
  REQUIRE(packet.has_ethernet);
  REQUIRE(packet.is_ipv4);
  REQUIRE(packet.is_tcp);
  REQUIRE(packet.src_port == 54321);
  REQUIRE(packet.dst_port == 22);
  REQUIRE(packet.tcp_flags == 0x02);
  REQUIRE(packet.payload_len == 4);

  packet.timestamp_us = 12'345'678;
  const std::string summary = minisnort::decoder::summarizePacket(packet);
  REQUIRE(summary.find("TCP 172.20.0.10:54321 -> 172.21.0.20:22") != std::string::npos);
  REQUIRE(summary.find("flags=S") != std::string::npos);
}

TEST_CASE("decode UDP packet") {
  const auto bytes = buildEthernetIpv4UdpPacket();
  minisnort::core::Packet packet;

  const bool ok = minisnort::decoder::decodePacket(bytes.data(), bytes.size(), packet);

  REQUIRE(ok);
  REQUIRE(packet.is_udp);
  REQUIRE(packet.src_port == 12345);
  REQUIRE(packet.dst_port == 53);
  REQUIRE(packet.payload_len == 4);
}

TEST_CASE("decode ICMP packet") {
  const auto bytes = buildEthernetIpv4IcmpPacket();
  minisnort::core::Packet packet;

  const bool ok = minisnort::decoder::decodePacket(bytes.data(), bytes.size(), packet);

  REQUIRE(ok);
  REQUIRE(packet.is_icmp);
  REQUIRE(packet.icmp_type == 8);
  REQUIRE(packet.icmp_code == 0);
  REQUIRE(packet.payload_len == 8);
}

TEST_CASE("reject unsupported non IPv4 ethertype") {
  const auto bytes = buildEthernetArpPacket();
  minisnort::core::Packet packet;

  const bool ok = minisnort::decoder::decodePacket(bytes.data(), bytes.size(), packet);

  REQUIRE_FALSE(ok);
}

TEST_CASE("reject truncated ethernet and truncated ipv4/tcp") {
  minisnort::core::Packet packet;

  const std::array<uint8_t, 10> short_ether{};
  REQUIRE_FALSE(minisnort::decoder::decodePacket(short_ether.data(), short_ether.size(), packet));

  auto bytes = buildEthernetIpv4TcpPacket();
  bytes[16] = 0x00;
  bytes[17] = 0x14;
  REQUIRE_FALSE(minisnort::decoder::decodePacket(bytes.data(), bytes.size(), packet));

  auto bytes2 = buildEthernetIpv4TcpPacket();
  bytes2[46] = 0x40;
  REQUIRE_FALSE(minisnort::decoder::decodePacket(bytes2.data(), bytes2.size(), packet));
}
