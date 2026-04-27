#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "core/packet.h"
#include "detection/engine.h"

namespace minisnort::logger {

class AlertFast {
 public:
  explicit AlertFast(std::string output_path);

  bool ok() const;
  const std::string& output_path() const;
  void emit(const core::Packet& packet, detection::Verdict verdict,
            const std::vector<detection::MatchedRule>& matched_rules);

 private:
  std::string format_ip(uint32_t ip) const;
  std::string format_proto(const core::Packet& packet) const;

  std::string output_path_;
  mutable std::mutex write_mu_;
};

}  // namespace minisnort::logger
