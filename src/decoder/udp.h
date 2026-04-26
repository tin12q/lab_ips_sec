#pragma once

#include <cstddef>
#include <cstdint>

#include "core/packet.h"

namespace minisnort::decoder {

bool decodeUdp(const uint8_t* data, size_t len, size_t l4_offset, core::Packet& packet);

}  // namespace minisnort::decoder
