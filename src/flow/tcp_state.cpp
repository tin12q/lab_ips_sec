#include "flow/tcp_state.h"

namespace minisnort::flow {
namespace {

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;

bool has_flag(uint8_t flags, uint8_t bit) {
  return (flags & bit) != 0;
}

}  // namespace

TcpState next_tcp_state(TcpState current, uint8_t flags, bool from_originator) {
  if (has_flag(flags, kTcpRst) || has_flag(flags, kTcpFin)) {
    return TcpState::kClosed;
  }

  switch (current) {
    case TcpState::kNew:
      if (from_originator && has_flag(flags, kTcpSyn) && !has_flag(flags, kTcpAck)) {
        return TcpState::kSynSent;
      }
      return current;
    case TcpState::kSynSent:
      if (!from_originator && has_flag(flags, kTcpSyn) && has_flag(flags, kTcpAck)) {
        return TcpState::kSynAckSeen;
      }
      return current;
    case TcpState::kSynAckSeen:
      if (from_originator && has_flag(flags, kTcpAck)) {
        return TcpState::kEstablished;
      }
      return current;
    case TcpState::kEstablished:
      return current;
    case TcpState::kClosed:
      return current;
  }

  return current;
}

bool is_established(TcpState state) {
  return state == TcpState::kEstablished;
}

}  // namespace minisnort::flow
