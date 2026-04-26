#include <limits>
#include <string>

#include "daq/nfq_daq.h"
#include "daq/pcap_daq.h"

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

}  // namespace

int main(int argc, char** argv) {
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
      minisnort::daq::NfqDaq daq;
      return daq.run(static_cast<int>(parsed_queue));
    } catch (...) {
      return 2;
    }
  }

  const std::string interface_name = get_arg_or_default(argc, argv, "-i", "eth0");
  minisnort::daq::PcapDaq daq;
  return daq.run(interface_name);
}
