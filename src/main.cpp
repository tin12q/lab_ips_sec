#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <cstdlib>
#include <vector>

#include <spdlog/spdlog.h>

#include "daq/nfq_daq.h"
#include "daq/pcap_daq.h"
#include "detection/engine.h"
#include "logger/alert_fast.h"
#include "rules/parser.h"
#include "rules/rule_store.h"
#include "util/config.h"

namespace {

std::string get_arg_or_default(int argc, char** argv, const std::string& key,
                               const std::string& fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == key) {
      return argv[i + 1];
    }
  }
  return fallback;
}

bool read_file(const std::string& path, std::string& content) {
  std::ifstream input(path);
  if (!input) {
    return false;
  }
  std::ostringstream oss;
  oss << input.rdbuf();
  content = oss.str();
  return true;
}

std::string join_sids(const std::vector<minisnort::rules::Rule>& rules) {
  std::ostringstream oss;
  for (size_t i = 0; i < rules.size(); ++i) {
    if (i > 0) {
      oss << ",";
    }
    oss << rules[i].sid;
  }
  return oss.str();
}

}  // namespace

int main(int argc, char** argv) {
  const std::string config_path =
      get_arg_or_default(argc, argv, "--config", "config/minisnort.yaml");
  minisnort::util::Config config;
  std::string config_error;
  if (!minisnort::util::load_config_file(config_path, config, config_error)) {
    spdlog::error("{}", config_error);
    return 2;
  }

  const std::string rules_path = get_arg_or_default(argc, argv, "--rules", config.rules_file);
  std::string rule_text;
  if (!read_file(rules_path, rule_text)) {
    spdlog::error("unable to open rules file: {}", rules_path);
    return 2;
  }

  minisnort::rules::Parser parser;
  const std::unordered_map<std::string, std::string> variables = {{"HOME_NET", config.home_net}};
  auto parsed = parser.parse_text(rule_text, variables);
  if (!parsed.ok()) {
    const auto& error = parsed.errors.front();
    spdlog::error("rule parse error at line {}: {}", error.line, error.message);
    return 2;
  }

  minisnort::rules::RuleStore rule_store;
  rule_store.set_rules(std::move(parsed.rules));
  spdlog::info("Loaded {} rules: SIDs [{}]", rule_store.rules().size(),
               join_sids(rule_store.rules()));

  if (config.log_level == "trace") {
    spdlog::set_level(spdlog::level::trace);
  } else if (config.log_level == "debug") {
    spdlog::set_level(spdlog::level::debug);
  } else if (config.log_level == "info") {
    spdlog::set_level(spdlog::level::info);
  } else if (config.log_level == "warn") {
    spdlog::set_level(spdlog::level::warn);
  } else if (config.log_level == "error") {
    spdlog::set_level(spdlog::level::err);
  } else if (config.log_level == "critical") {
    spdlog::set_level(spdlog::level::critical);
  } else if (config.log_level == "off") {
    spdlog::set_level(spdlog::level::off);
  }

  const std::filesystem::path alert_path(config.alert_file);
  const auto alert_dir = alert_path.parent_path();
  if (!alert_dir.empty()) {
    std::error_code mkdir_error;
    std::filesystem::create_directories(alert_dir, mkdir_error);
    if (mkdir_error) {
      spdlog::error("unable to create alert log directory {}: {}", alert_dir.string(),
                    mkdir_error.message());
      return 2;
    }
  }

  minisnort::logger::AlertFast alert_logger(config.alert_file);
  if (!alert_logger.ok()) {
    spdlog::error("unable to open alert log file: {}", alert_logger.output_path());
    return 2;
  }
  spdlog::info("Alert fast log file: {}", alert_logger.output_path());

  minisnort::detection::Engine engine(rule_store);

  const std::string mode = get_arg_or_default(argc, argv, "--mode", "ids");
  if (mode == "ips") {
    const std::string queue_value = get_arg_or_default(argc, argv, "--queue", "0");
    try {
      size_t parsed_len = 0;
      const long parsed_queue = std::stol(queue_value, &parsed_len);
      if (parsed_len != queue_value.size() || parsed_queue < 0 ||
          parsed_queue > std::numeric_limits<int>::max()) {
        return 2;
      }
      const char* fail_open_env = std::getenv("MINISNORT_FAIL_OPEN");
      minisnort::daq::NfqDaq daq(fail_open_env != nullptr && std::string(fail_open_env) == "1");
      return daq.run(static_cast<int>(parsed_queue), engine, alert_logger);
    } catch (...) {
      return 2;
    }
  }

  const std::string interface_name = get_arg_or_default(argc, argv, "-i", "eth0");
  minisnort::daq::PcapDaq daq;
  return daq.run(interface_name, engine, alert_logger);
}
