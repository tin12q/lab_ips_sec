#pragma once

#include <string>

namespace minisnort::daq {

class IDaq {
 public:
  virtual ~IDaq() = default;
  virtual int run(const std::string& source) = 0;
};

}  // namespace minisnort::daq
