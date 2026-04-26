#pragma once

#include <cstddef>
#include <cstdint>

#include "core/packet.h"

namespace minisnort::decoder {

bool decodeIpv4(const uint8_t* data, size_t len, size_t l3_offset, core::Packet& packet,
                size_t& l4_offset);

}  // namespace minisnort::decoder
