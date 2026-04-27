#include "daq/pcap_daq.h"

#include <pcap/pcap.h>
#include <spdlog/spdlog.h>

#include "decoder/decoder.h"

namespace minisnort::daq {

namespace {
constexpr int kCaptureCount = 5;

struct PcapContext {
  int captured = 0;
  detection::Engine* engine = nullptr;
  logger::AlertFast* alert_logger = nullptr;
};

void handle_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
  auto* ctx = reinterpret_cast<PcapContext*>(user);
  if (ctx == nullptr || ctx->engine == nullptr || ctx->alert_logger == nullptr) {
    return;
  }
  ++ctx->captured;

  core::Packet decoded;
  if (!decoder::decodePacket(packet, header->caplen, decoded)) {
    return;
  }

  const uint64_t sec = static_cast<uint64_t>(header->ts.tv_sec);
  const uint64_t usec = static_cast<uint64_t>(header->ts.tv_usec);
  decoded.timestamp_us = sec * 1000000ULL + usec;

  const auto decision = ctx->engine->inspect(decoded);
  if (!decision.matched_rules.empty()) {
    ctx->alert_logger->emit(decoded, decision.verdict, decision.matched_rules);
    spdlog::info("[pcap] verdict={} matched_rules={}",
                 decision.verdict == detection::Verdict::kDrop ? "drop" : "accept",
                 decision.matched_rules.size());
  }
}
}  // namespace

int PcapDaq::run(const std::string& interface_name, detection::Engine& engine,
                 logger::AlertFast& alert_logger) const {
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    spdlog::error("[pcap] open failed on {}: {}", interface_name, errbuf);
    return 1;
  }

  PcapContext ctx;
  ctx.engine = &engine;
  ctx.alert_logger = &alert_logger;
  const int rc = pcap_loop(handle, kCaptureCount, handle_packet, reinterpret_cast<u_char*>(&ctx));

  pcap_close(handle);

  if (rc == -1) {
    spdlog::error("[pcap] loop failed");
    return 1;
  }

  spdlog::info("[pcap] capture finished on {}, packets={}", interface_name, ctx.captured);
  return 0;
}

}  // namespace minisnort::daq
