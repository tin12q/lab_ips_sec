#pragma once

#include <string>

#include "detection/engine.h"
#include "logger/alert_fast.h"

namespace minisnort::daq {

class PcapDaq {
 public:
  int run(const std::string& interface_name, detection::Engine& engine,
          logger::AlertFast& alert_logger) const;
};

}  // namespace minisnort::daq
