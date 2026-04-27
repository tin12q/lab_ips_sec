#include "flow/flow_table.h"

#include <utility>

namespace minisnort::flow {
namespace {

constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpAck = 0x10;

bool is_syn_without_ack(uint8_t flags) {
  return (flags & kTcpSyn) != 0 && (flags & kTcpAck) == 0;
}

}  // namespace

FlowKey FlowKey::from_packet(const core::Packet& packet) {
  const bool forward_order = (packet.src_ip < packet.dst_ip) ||
                             (packet.src_ip == packet.dst_ip && packet.src_port <= packet.dst_port);

  if (forward_order) {
    return FlowKey{packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.l3_proto};
  }

  return FlowKey{packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.l3_proto};
}

std::size_t FlowKeyHash::operator()(const FlowKey& key) const {
  const std::size_t h1 = std::hash<uint32_t>{}(key.ip_a);
  const std::size_t h2 = std::hash<uint32_t>{}(key.ip_b);
  const std::size_t h3 = std::hash<uint16_t>{}(key.port_a);
  const std::size_t h4 = std::hash<uint16_t>{}(key.port_b);
  const std::size_t h5 = std::hash<uint8_t>{}(key.l4_proto);
  return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
}

bool FlowTable::is_tcp_packet(const core::Packet& packet) {
  return packet.is_tcp;
}

bool FlowTable::has_originator_hint(const core::Packet& packet) {
  return is_syn_without_ack(packet.tcp_flags);
}

std::optional<std::pair<uint32_t, uint16_t>> FlowTable::infer_originator(const core::Packet& packet) {
  if (!packet.is_tcp) {
    return std::nullopt;
  }

  if (has_originator_hint(packet)) {
    return std::make_pair(packet.src_ip, packet.src_port);
  }

  return std::nullopt;
}

FlowSnapshot FlowTable::update_and_get(const core::Packet& packet) {
  if (!is_tcp_packet(packet) || !packet.is_ipv4) {
    return FlowSnapshot{};
  }

  const FlowKey key = FlowKey::from_packet(packet);
  auto& entry = table_[key];

  if (!entry.has_originator) {
    if (const auto originator = infer_originator(packet); originator.has_value()) {
      entry.client_ip = originator->first;
      entry.client_port = originator->second;
      entry.has_originator = true;
    }
  }

  if (!entry.has_originator) {
    entry.client_ip = packet.src_ip;
    entry.client_port = packet.src_port;
    entry.has_originator = true;
  }

  const bool from_originator = packet.src_ip == entry.client_ip && packet.src_port == entry.client_port;
  entry.tcp_state = next_tcp_state(entry.tcp_state, packet.tcp_flags, from_originator);

  const FlowSnapshot snapshot{from_originator, is_established(entry.tcp_state)};

  if (entry.tcp_state == TcpState::kClosed) {
    table_.erase(key);
  }

  return snapshot;
}

}  // namespace minisnort::flow
