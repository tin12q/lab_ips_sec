#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>

#include "core/packet.h"
#include "rules/rule.h"

namespace minisnort::detection {

class Threshold {
 public:
  bool allow(const rules::Rule& rule, const core::Packet& packet);

 private:
  struct ThresholdKey {
    uint32_t sid = 0;
    uint32_t track_value = 0;

    bool operator==(const ThresholdKey& other) const {
      return sid == other.sid && track_value == other.track_value;
    }
  };

  struct ThresholdKeyHash {
    std::size_t operator()(const ThresholdKey& key) const;
  };

  static std::optional<ThresholdKey> make_key(const rules::Rule& rule, const core::Packet& packet);

  std::unordered_map<ThresholdKey, std::deque<uint64_t>, ThresholdKeyHash> windows_;
};

}  // namespace minisnort::detection
