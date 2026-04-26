#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace minisnort::core {

struct Packet {
  const uint8_t* raw = nullptr;
  size_t raw_len = 0;

  uint8_t l3_proto = 0;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t tcp_flags = 0;
  uint8_t icmp_type = 0;
  uint8_t icmp_code = 0;

  const uint8_t* payload = nullptr;
  size_t payload_len = 0;

  uint64_t timestamp_us = 0;
  uint32_t nfq_packet_id = 0;

  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  uint16_t ether_type = 0;
  bool has_ethernet = false;
  bool is_ipv4 = false;
  bool is_tcp = false;
  bool is_udp = false;
  bool is_icmp = false;
};

struct PacketSummary {
  std::string text;
};

}  // namespace minisnort::core
