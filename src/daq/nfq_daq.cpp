#include "daq/nfq_daq.h"

#include <spdlog/spdlog.h>

#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace minisnort::daq {

#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
namespace {

int callback(nfq_q_handle* queue_handle, nfgenmsg* nfmsg, nfq_data* data, void* user_data) {
  (void)nfmsg;
  (void)user_data;

  nfqnl_msg_packet_hdr* packet_header = nfq_get_msg_packet_hdr(data);
  if (packet_header == nullptr) {
    return 0;
  }

  const uint32_t packet_id = ntohl(packet_header->packet_id);
  unsigned char* payload = nullptr;
  const int payload_len = nfq_get_payload(data, &payload);
  (void)payload;

  spdlog::info("[nfq] Got packet id={}, len={}", packet_id, payload_len);
  return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, nullptr);
}

}  // namespace
#endif

int NfqDaq::run(int queue_num) const {
#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
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

  nfq_q_handle* queue_handle = nfq_create_queue(handle, static_cast<uint16_t>(queue_num),
                                                 &callback, nullptr);
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
      break;
    }
    nfq_handle_packet(handle, buf, rv);
  }

  nfq_destroy_queue(queue_handle);
  nfq_close(handle);
  return 0;
#else
  spdlog::warn("[nfq] netfilter_queue headers unavailable; placeholder mode for queue {}", queue_num);
  return 0;
#endif
}

}  // namespace minisnort::daq
