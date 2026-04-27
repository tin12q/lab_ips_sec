#include "util/config.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>

namespace minisnort::util {
namespace {

std::string trim(const std::string& value) {
  size_t first = 0;
  while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
    ++first;
  }

  size_t last = value.size();
  while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) {
    --last;
  }

  return value.substr(first, last - first);
}

std::string unquote(const std::string& value) {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    return value.substr(1, value.size() - 2);
  }
  return value;
}

bool starts_with(const std::string& value, const std::string& prefix) {
  return value.rfind(prefix, 0) == 0;
}

}  // namespace

bool load_config_file(const std::string& path, Config& out, std::string& error) {
  std::ifstream input(path);
  if (!input) {
    error = "unable to open config: " + path;
    return false;
  }

  bool has_home_net = false;
  bool has_rules_file = false;
  bool has_alert_file = false;
  std::string line;
  std::string section;
  size_t line_no = 0;
  while (std::getline(input, line)) {
    ++line_no;
    const std::string t = trim(line);
    if (t.empty() || t[0] == '#') {
      continue;
    }

    if (t.size() > 1 && t.back() == ':') {
      section = t.substr(0, t.size() - 1);
      continue;
    }

    if (section == "networks") {
      if (!starts_with(t, "home_net:")) {
        continue;
      }
      const std::string value = unquote(trim(t.substr(9)));
      if (value.empty()) {
        error = "home_net cannot be empty at line " + std::to_string(line_no);
        return false;
      }
      out.home_net = value;
      has_home_net = true;
      continue;
    }

    if (section == "rules") {
      if (!starts_with(t, "file:")) {
        continue;
      }
      const std::string value = unquote(trim(t.substr(5)));
      if (value.empty()) {
        error = "rules.file cannot be empty at line " + std::to_string(line_no);
        return false;
      }
      out.rules_file = value;
      has_rules_file = true;
      continue;
    }

    if (section == "logging") {
      if (starts_with(t, "alert_file:")) {
        const std::string value = unquote(trim(t.substr(11)));
        if (value.empty()) {
          error = "logging.alert_file cannot be empty at line " + std::to_string(line_no);
          return false;
        }

        const std::filesystem::path alert_path(value);
        if (!alert_path.is_absolute()) {
          error = "logging.alert_file must be an absolute path at line " + std::to_string(line_no);
          return false;
        }

        bool has_parent_ref = false;
        for (const auto& part : alert_path) {
          if (part == "..") {
            has_parent_ref = true;
            break;
          }
        }
        if (has_parent_ref) {
          error = "logging.alert_file cannot contain '..' at line " + std::to_string(line_no);
          return false;
        }

        out.alert_file = value;
        has_alert_file = true;
        continue;
      }

      if (starts_with(t, "level:")) {
        const std::string value = unquote(trim(t.substr(6)));
        if (value == "trace" || value == "debug" || value == "info" || value == "warn" ||
            value == "error" || value == "critical" || value == "off") {
          out.log_level = value;
          continue;
        }
        error = "logging.level invalid at line " + std::to_string(line_no);
        return false;
      }

      continue;
    }

    // Ignore sections unrelated to runtime config loading.
  }

  if (!has_home_net) {
    error = "missing required config key: networks.home_net";
    return false;
  }
  if (!has_rules_file) {
    error = "missing required config key: rules.file";
    return false;
  }
  if (!has_alert_file) {
    error = "missing required config key: logging.alert_file";
    return false;
  }

  return true;
}

}  // namespace minisnort::util
