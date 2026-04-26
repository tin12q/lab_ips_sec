#include "decoder/icmp.h"

namespace minisnort::decoder {

bool decodeIcmp(const uint8_t* data, size_t len, size_t l4_offset, core::Packet& packet) {
  constexpr size_t kIcmpMinLen = 4;
  if (data == nullptr || l4_offset > len || (len - l4_offset) < kIcmpMinLen ||
      packet.payload_len < kIcmpMinLen) {
    return false;
  }

  const uint8_t* icmp = data + l4_offset;
  packet.icmp_type = icmp[0];
  packet.icmp_code = icmp[1];
  packet.is_icmp = true;

  packet.payload = data + l4_offset + kIcmpMinLen;
  packet.payload_len -= kIcmpMinLen;
  return true;
}

}  // namespace minisnort::decoder
