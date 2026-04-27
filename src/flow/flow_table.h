#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>

#include "core/packet.h"
#include "flow/flow_key.h"
#include "flow/tcp_state.h"

namespace minisnort::flow {

struct FlowSnapshot {
  bool to_server = false;
  bool established = false;
};

class FlowTable {
 public:
  FlowSnapshot update_and_get(const core::Packet& packet);

 private:
  struct FlowEntry {
    uint32_t client_ip = 0;
    uint16_t client_port = 0;
    TcpState tcp_state = TcpState::kNew;
    bool has_originator = false;
  };

  std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> table_;

  static bool is_tcp_packet(const core::Packet& packet);
  static bool has_originator_hint(const core::Packet& packet);
  static std::optional<std::pair<uint32_t, uint16_t>> infer_originator(const core::Packet& packet);
};

}  // namespace minisnort::flow
