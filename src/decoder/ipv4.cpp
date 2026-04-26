#include "decoder/ipv4.h"

namespace minisnort::decoder {

bool decodeIpv4(const uint8_t* data, size_t len, size_t l3_offset, core::Packet& packet,
                size_t& l4_offset) {
  constexpr size_t kIpv4MinHeaderLen = 20;
  if (data == nullptr || l3_offset > len || (len - l3_offset) < kIpv4MinHeaderLen) {
    return false;
  }

  const uint8_t* ip = data + l3_offset;
  const uint8_t version = static_cast<uint8_t>(ip[0] >> 4U);
  if (version != 4) {
    return false;
  }

  const uint8_t ihl = static_cast<uint8_t>(ip[0] & 0x0F);
  const size_t ip_header_len = static_cast<size_t>(ihl) * 4U;
  if (ihl < 5 || ip_header_len > (len - l3_offset)) {
    return false;
  }

  const uint16_t total_len = static_cast<uint16_t>((static_cast<uint16_t>(ip[2]) << 8U) | ip[3]);
  if (total_len < ip_header_len || total_len > (len - l3_offset)) {
    return false;
  }

  packet.is_ipv4 = true;
  packet.l3_proto = ip[9];
  packet.src_ip = (static_cast<uint32_t>(ip[12]) << 24U) | (static_cast<uint32_t>(ip[13]) << 16U) |
                  (static_cast<uint32_t>(ip[14]) << 8U) | static_cast<uint32_t>(ip[15]);
  packet.dst_ip = (static_cast<uint32_t>(ip[16]) << 24U) | (static_cast<uint32_t>(ip[17]) << 16U) |
                  (static_cast<uint32_t>(ip[18]) << 8U) | static_cast<uint32_t>(ip[19]);

  l4_offset = l3_offset + ip_header_len;
  packet.payload = data + l4_offset;
  packet.payload_len = static_cast<size_t>(total_len) - ip_header_len;
  return true;
}

}  // namespace minisnort::decoder
