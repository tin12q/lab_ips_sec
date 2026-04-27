#include "detection/threshold.h"

#include <cstddef>

namespace minisnort::detection {

std::size_t Threshold::ThresholdKeyHash::operator()(const ThresholdKey& key) const {
  const std::size_t sid_hash = std::hash<uint32_t>{}(key.sid);
  const std::size_t track_hash = std::hash<uint32_t>{}(key.track_value);
  return sid_hash ^ (track_hash + 0x9e3779b9 + (sid_hash << 6) + (sid_hash >> 2));
}

std::optional<Threshold::ThresholdKey> Threshold::make_key(const rules::Rule& rule,
                                                           const core::Packet& packet) {
  if (!rule.threshold.has_value()) {
    return std::nullopt;
  }

  const auto track = rule.threshold->track;
  const uint32_t track_value =
      track == rules::ThresholdOpt::Track::kBySrc ? packet.src_ip : packet.dst_ip;
  return ThresholdKey{rule.sid, track_value};
}

bool Threshold::allow(const rules::Rule& rule, const core::Packet& packet) {
  if (!rule.threshold.has_value()) {
    return true;
  }

  const auto key = make_key(rule, packet);
  if (!key.has_value()) {
    return true;
  }

  auto& window = windows_[*key];
  const uint64_t now = packet.timestamp_us;
  const uint64_t window_us = static_cast<uint64_t>(rule.threshold->seconds) * 1000000ULL;

  while (!window.empty() && now >= window.front() && (now - window.front()) >= window_us) {
    window.pop_front();
  }

  window.push_back(now);
  if (static_cast<int>(window.size()) < rule.threshold->count) {
    return false;
  }

  window.clear();
  return true;
}

}  // namespace minisnort::detection
