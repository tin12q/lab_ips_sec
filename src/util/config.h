#pragma once

#include <string>

namespace minisnort::util {

struct Config {
  std::string home_net = "10.201.0.0/24";
  std::string rules_file = "config/rules/local.rules";
  std::string alert_file = "/var/log/minisnort/alert.log";
  std::string log_level = "info";
};

bool load_config_file(const std::string& path, Config& out, std::string& error);

}  // namespace minisnort::util
