#include "daq/nfq_daq.h"

#include <spdlog/spdlog.h>

#include <vector>

#include "decoder/decoder.h"

#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <cerrno>
#include <chrono>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace minisnort::daq {

#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
namespace {

struct NfqContext {
  detection::Engine* engine = nullptr;
  logger::AlertFast* alert_logger = nullptr;
};

int callback(nfq_q_handle* queue_handle, nfgenmsg* nfmsg, nfq_data* data, void* user_data) {
  (void)nfmsg;

  nfqnl_msg_packet_hdr* packet_header = nfq_get_msg_packet_hdr(data);
  if (packet_header == nullptr) {
    spdlog::warn("[nfq] missing packet header; fail-open without packet_id");
    return NF_ACCEPT;
  }

  const uint32_t packet_id = ntohl(packet_header->packet_id);
  auto* ctx = reinterpret_cast<NfqContext*>(user_data);
  if (ctx == nullptr || ctx->engine == nullptr || ctx->alert_logger == nullptr) {
    spdlog::warn("[nfq] fail-open: invalid callback context");
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, nullptr);
  }

  unsigned char* payload = nullptr;
  const int payload_len = nfq_get_payload(data, &payload);
  if (payload_len <= 0 || payload == nullptr) {
    spdlog::warn("[nfq] fail-open: empty payload for packet_id={}", packet_id);
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, nullptr);
  }

  core::Packet decoded;
  bool decode_ok = decoder::decodePacket(payload, static_cast<size_t>(payload_len), decoded);

  if (!decode_ok) {
    // NFQ payload is typically L3 (IP) without an Ethernet header.
    // Build a minimal synthetic Ethernet+IPv4 frame so the existing decoder path remains reusable.
    constexpr size_t kEthernetHeaderLen = 14;
    std::vector<uint8_t> framed_payload(kEthernetHeaderLen + static_cast<size_t>(payload_len), 0);
    framed_payload[12] = 0x08;
    framed_payload[13] = 0x00;
    for (int i = 0; i < payload_len; ++i) {
      framed_payload[kEthernetHeaderLen + static_cast<size_t>(i)] = payload[static_cast<size_t>(i)];
    }

    decode_ok = decoder::decodePacket(framed_payload.data(), framed_payload.size(), decoded);
    if (!decode_ok) {
      spdlog::warn("[nfq] fail-open: decode failed for packet_id={} payload_len={}", packet_id,
                   payload_len);
      return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, nullptr);
    }

    spdlog::info("[nfq] decoded packet_id={} using synthetic L2 framing", packet_id);
  }

  const auto now = std::chrono::system_clock::now();
  const uint64_t now_us = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count());
  decoded.timestamp_us = now_us;
  decoded.nfq_packet_id = packet_id;

  const auto decision = ctx->engine->inspect(decoded);
  if (!decision.matched_sids.empty()) {
    ctx->alert_logger->emit(decoded, decision.verdict, decision.matched_sids);
  }

  const uint32_t verdict = decision.verdict == detection::Verdict::kDrop ? NF_DROP : NF_ACCEPT;
  spdlog::info("[nfq] packet_id={} verdict={} matched_sids={}", packet_id,
               decision.verdict == detection::Verdict::kDrop ? "drop" : "accept",
               decision.matched_sids.size());
  return nfq_set_verdict(queue_handle, packet_id, verdict, 0, nullptr);
}

}  // namespace
#endif

int NfqDaq::run(int queue_num, detection::Engine& engine,
                logger::AlertFast& alert_logger) const {
#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
  if (queue_num < 0 || queue_num > 65535) {
    spdlog::error("[nfq] queue number out of range: {}", queue_num);
    return 1;
  }

  nfq_handle* handle = nfq_open();
  if (handle == nullptr) {
    spdlog::error("[nfq] nfq_open failed");
    return 1;
  }

  if (nfq_unbind_pf(handle, AF_INET) < 0) {
    spdlog::warn("[nfq] nfq_unbind_pf failed; continuing");
  }

  if (nfq_bind_pf(handle, AF_INET) < 0) {
    spdlog::error("[nfq] nfq_bind_pf failed");
    nfq_close(handle);
    return 1;
  }

  NfqContext ctx;
  ctx.engine = &engine;
  ctx.alert_logger = &alert_logger;
  nfq_q_handle* queue_handle =
      nfq_create_queue(handle, static_cast<uint16_t>(queue_num), &callback, &ctx);
  if (queue_handle == nullptr) {
    spdlog::error("[nfq] nfq_create_queue failed");
    nfq_close(handle);
    return 1;
  }

  if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
    spdlog::error("[nfq] nfq_set_mode failed");
    nfq_destroy_queue(queue_handle);
    nfq_close(handle);
    return 1;
  }

  const int fd = nfq_fd(handle);
  char buf[4096] __attribute__((aligned));

  spdlog::info("[nfq] listening on queue {}", queue_num);

  while (true) {
    const int rv = recv(fd, buf, sizeof(buf), 0);
    if (rv < 0) {
      if (errno == EINTR) {
        continue;
      }
      spdlog::error("[nfq] recv failed");
      break;
    }
    if (rv == 0) {
      spdlog::warn("[nfq] recv returned zero-length payload; stopping");
      break;
    }
    nfq_handle_packet(handle, buf, rv);
  }

  nfq_destroy_queue(queue_handle);
  nfq_close(handle);
  return 0;
#else
  (void)engine;
  spdlog::warn("[nfq] netfilter_queue headers unavailable; placeholder mode for queue {}", queue_num);
  return 0;
#endif
}

}  // namespace minisnort::daq
