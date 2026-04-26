#pragma once

#include <cstddef>
#include <cstdint>

#include "core/packet.h"

namespace minisnort::decoder {

bool decodeEthernet(const uint8_t* data, size_t len, core::Packet& packet,
                    size_t& l3_offset);

}  // namespace minisnort::decoder
