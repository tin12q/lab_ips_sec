#include "decoder/decoder.h"

#include <cstdio>
#include <sstream>

#include "decoder/ethernet.h"
#include "decoder/icmp.h"
#include "decoder/ipv4.h"
#include "decoder/tcp.h"
#include "decoder/udp.h"

namespace minisnort::decoder {
namespace {

std::string ipToString(uint32_t ip) {
  std::ostringstream oss;
  oss << ((ip >> 24U) & 0xFFU) << '.' << ((ip >> 16U) & 0xFFU) << '.' << ((ip >> 8U) & 0xFFU)
      << '.' << (ip & 0xFFU);
  return oss.str();
}

std::string tcpFlagsToString(uint8_t flags) {
  std::string out;
  if ((flags & 0x02U) != 0U) out.push_back('S');
  if ((flags & 0x10U) != 0U) out.push_back('A');
  if ((flags & 0x01U) != 0U) out.push_back('F');
  if ((flags & 0x04U) != 0U) out.push_back('R');
  if ((flags & 0x08U) != 0U) out.push_back('P');
  if ((flags & 0x20U) != 0U) out.push_back('U');
  if (out.empty()) out = "-";
  return out;
}

}  // namespace

bool decodePacket(const uint8_t* data, size_t len, core::Packet& packet) {
  packet = core::Packet{};
  packet.raw = data;
  packet.raw_len = len;

  size_t l3_offset = 0;
  if (!decodeEthernet(data, len, packet, l3_offset)) {
    return false;
  }

  if (packet.ether_type != 0x0800U) {
    return false;
  }

  size_t l4_offset = 0;
  if (!decodeIpv4(data, len, l3_offset, packet, l4_offset)) {
    return false;
  }

  switch (packet.l3_proto) {
    case 6:
      return decodeTcp(data, len, l4_offset, packet);
    case 17:
      return decodeUdp(data, len, l4_offset, packet);
    case 1:
      return decodeIcmp(data, len, l4_offset, packet);
    default:
      return true;
  }
}

std::string summarizePacket(const core::Packet& packet) {
  char time_buf[32] = {0};
  const unsigned long long sec = static_cast<unsigned long long>(packet.timestamp_us / 1000000ULL);
  const unsigned long long ms = static_cast<unsigned long long>((packet.timestamp_us % 1000000ULL) / 1000ULL);
  std::snprintf(time_buf, sizeof(time_buf), "[%06llu.%03llu]", sec, ms);

  std::ostringstream oss;
  oss << time_buf << ' ';

  if (packet.is_tcp) {
    oss << "TCP " << ipToString(packet.src_ip) << ':' << packet.src_port << " -> "
        << ipToString(packet.dst_ip) << ':' << packet.dst_port << " flags="
        << tcpFlagsToString(packet.tcp_flags);
  } else if (packet.is_udp) {
    oss << "UDP " << ipToString(packet.src_ip) << ':' << packet.src_port << " -> "
        << ipToString(packet.dst_ip) << ':' << packet.dst_port;
  } else if (packet.is_icmp) {
    oss << "ICMP " << ipToString(packet.src_ip) << " -> " << ipToString(packet.dst_ip)
        << " type=" << static_cast<unsigned>(packet.icmp_type)
        << " code=" << static_cast<unsigned>(packet.icmp_code);
  } else if (packet.is_ipv4) {
    oss << "IP " << ipToString(packet.src_ip) << " -> " << ipToString(packet.dst_ip)
        << " proto=" << static_cast<unsigned>(packet.l3_proto);
  } else {
    oss << "UNKNOWN";
  }

  oss << " len=" << packet.raw_len;
  return oss.str();
}

}  // namespace minisnort::decoder
