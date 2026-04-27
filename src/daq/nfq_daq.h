#pragma once

#include "detection/engine.h"
#include "logger/alert_fast.h"

namespace minisnort::daq {

class NfqDaq {
 public:
  explicit NfqDaq(bool fail_open = false);

  int run(int queue_num, detection::Engine& engine, logger::AlertFast& alert_logger) const;

 private:
  bool fail_open_ = false;
};

}  // namespace minisnort::daq
