#include "decoder/ethernet.h"

#include <algorithm>

namespace minisnort::decoder {

bool decodeEthernet(const uint8_t* data, size_t len, core::Packet& packet,
                    size_t& l3_offset) {
  constexpr size_t kEthernetHeaderLen = 14;
  if (data == nullptr || len < kEthernetHeaderLen) {
    return false;
  }

  packet.raw = data;
  packet.raw_len = len;

  std::copy(data, data + 6, packet.dst_mac.begin());
  std::copy(data + 6, data + 12, packet.src_mac.begin());

  packet.ether_type = static_cast<uint16_t>((static_cast<uint16_t>(data[12]) << 8U) | data[13]);
  packet.has_ethernet = true;

  l3_offset = kEthernetHeaderLen;
  return true;
}

}  // namespace minisnort::decoder
