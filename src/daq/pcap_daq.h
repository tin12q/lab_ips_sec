#pragma once

#include <string>

namespace minisnort::daq {

class PcapDaq {
 public:
  int run(const std::string& interface_name) const;
};

}  // namespace minisnort::daq
