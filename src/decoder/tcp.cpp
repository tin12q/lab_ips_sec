#include "decoder/tcp.h"

namespace minisnort::decoder {

bool decodeTcp(const uint8_t* data, size_t len, size_t l4_offset, core::Packet& packet) {
  constexpr size_t kTcpMinHeaderLen = 20;
  if (data == nullptr || l4_offset > len || (len - l4_offset) < kTcpMinHeaderLen) {
    return false;
  }

  const uint8_t* tcp = data + l4_offset;
  const uint16_t src_port = static_cast<uint16_t>((static_cast<uint16_t>(tcp[0]) << 8U) | tcp[1]);
  const uint16_t dst_port = static_cast<uint16_t>((static_cast<uint16_t>(tcp[2]) << 8U) | tcp[3]);
  const uint8_t data_offset_words = static_cast<uint8_t>(tcp[12] >> 4U);
  const size_t header_len = static_cast<size_t>(data_offset_words) * 4U;

  if (data_offset_words < 5 || header_len > (len - l4_offset) || header_len > packet.payload_len) {
    return false;
  }

  packet.src_port = src_port;
  packet.dst_port = dst_port;
  packet.tcp_flags = tcp[13];
  packet.is_tcp = true;

  packet.payload = data + l4_offset + header_len;
  packet.payload_len -= header_len;
  return true;
}

}  // namespace minisnort::decoder
