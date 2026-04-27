#pragma once

#include "detection/engine.h"
#include "logger/alert_fast.h"

namespace minisnort::daq {

class NfqDaq {
 public:
  int run(int queue_num, detection::Engine& engine, logger::AlertFast& alert_logger) const;
};

}  // namespace minisnort::daq
