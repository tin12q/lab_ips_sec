#include "decoder/udp.h"

namespace minisnort::decoder {

bool decodeUdp(const uint8_t* data, size_t len, size_t l4_offset, core::Packet& packet) {
  constexpr size_t kUdpHeaderLen = 8;
  if (data == nullptr || l4_offset > len || (len - l4_offset) < kUdpHeaderLen ||
      packet.payload_len < kUdpHeaderLen) {
    return false;
  }

  const uint8_t* udp = data + l4_offset;
  const uint16_t src_port = static_cast<uint16_t>((static_cast<uint16_t>(udp[0]) << 8U) | udp[1]);
  const uint16_t dst_port = static_cast<uint16_t>((static_cast<uint16_t>(udp[2]) << 8U) | udp[3]);
  const uint16_t udp_len = static_cast<uint16_t>((static_cast<uint16_t>(udp[4]) << 8U) | udp[5]);

  if (udp_len < kUdpHeaderLen || udp_len > packet.payload_len) {
    return false;
  }

  packet.src_port = src_port;
  packet.dst_port = dst_port;
  packet.is_udp = true;

  packet.payload = data + l4_offset + kUdpHeaderLen;
  packet.payload_len = static_cast<size_t>(udp_len) - kUdpHeaderLen;
  return true;
}

}  // namespace minisnort::decoder
