#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "core/packet.h"

namespace minisnort::decoder {

bool decodePacket(const uint8_t* data, size_t len, core::Packet& packet);
std::string summarizePacket(const core::Packet& packet);

}  // namespace minisnort::decoder
