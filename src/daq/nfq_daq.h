#pragma once

namespace minisnort::daq {

class NfqDaq {
 public:
  int run(int queue_num) const;
};

}  // namespace minisnort::daq
