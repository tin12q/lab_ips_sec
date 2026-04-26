#include "daq/pcap_daq.h"

#include <pcap/pcap.h>
#include <spdlog/spdlog.h>

namespace minisnort::daq {

namespace {
constexpr int kCaptureCount = 5;

void handle_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
  (void)packet;
  auto* count = reinterpret_cast<int*>(user);
  ++(*count);
  spdlog::info("[pcap] Got packet, len={}", header->len);
}
}  // namespace

int PcapDaq::run(const std::string& interface_name) const {
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    spdlog::error("[pcap] open failed on {}: {}", interface_name, errbuf);
    return 1;
  }

  int captured = 0;
  const int rc = pcap_loop(handle, kCaptureCount, handle_packet,
                           reinterpret_cast<u_char*>(&captured));

  pcap_close(handle);

  if (rc == -1) {
    spdlog::error("[pcap] loop failed");
    return 1;
  }

  spdlog::info("[pcap] capture finished on {}, packets={}", interface_name, captured);
  return 0;
}

}  // namespace minisnort::daq
