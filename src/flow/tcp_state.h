#pragma once

#include <cstdint>

namespace minisnort::flow {

enum class TcpState {
  kNew,
  kSynSent,
  kSynAckSeen,
  kEstablished,
  kClosed,
};

TcpState next_tcp_state(TcpState current, uint8_t flags, bool from_originator);
bool is_established(TcpState state);

}  // namespace minisnort::flow
