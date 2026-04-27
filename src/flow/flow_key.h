#pragma once

#include <cstddef>
#include <cstdint>

#include "core/packet.h"

namespace minisnort::flow {

struct FlowKey {
  uint32_t ip_a = 0;
  uint32_t ip_b = 0;
  uint16_t port_a = 0;
  uint16_t port_b = 0;
  uint8_t l4_proto = 0;

  bool operator==(const FlowKey& other) const {
    return ip_a == other.ip_a && ip_b == other.ip_b && port_a == other.port_a &&
           port_b == other.port_b && l4_proto == other.l4_proto;
  }

  static FlowKey from_packet(const core::Packet& packet);
};

struct FlowKeyHash {
  std::size_t operator()(const FlowKey& key) const;
};

}  // namespace minisnort::flow
