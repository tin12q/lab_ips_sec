#include "logger/alert_fast.h"

#include <arpa/inet.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

#include <spdlog/spdlog.h>

#include "rules/rule.h"

namespace minisnort::logger {

AlertFast::AlertFast(std::string output_path) : output_path_(std::move(output_path)) {
  std::ofstream out(output_path_, std::ios::app);
}

bool AlertFast::ok() const {
  std::ofstream out(output_path_, std::ios::app);
  return out.good();
}

const std::string& AlertFast::output_path() const { return output_path_; }

void AlertFast::emit(const core::Packet& packet, detection::Verdict verdict,
                     const std::vector<detection::MatchedRule>& matched_rules) {
  if (matched_rules.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(write_mu_);
  std::ofstream out(output_path_, std::ios::app);
  if (!out) {
    spdlog::error("[alert_fast] unable to open alert file: {}", output_path_);
    return;
  }

  const auto now = std::chrono::system_clock::now();
  const std::time_t now_tt = std::chrono::system_clock::to_time_t(now);
  const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
      now.time_since_epoch()) % std::chrono::seconds(1);
  std::tm tm{};
  localtime_r(&now_tt, &tm);

  std::ostringstream ts;
  ts << std::put_time(&tm, "%m/%d-%H:%M:%S") << '.' << std::setw(6) << std::setfill('0')
     << micros.count();

  const std::string proto = format_proto(packet);
  const std::string src = format_ip(packet.src_ip);
  const std::string dst = format_ip(packet.dst_ip);
  const std::string verdict_text = verdict == detection::Verdict::kDrop ? "drop" : "accept";

  for (const auto& rule : matched_rules) {
    const std::string action_text = rule.action == rules::Action::kDrop ? "drop"
                                    : rule.action == rules::Action::kPass ? "pass"
                                                                           : "alert";
    const std::string reason = rule.action == rules::Action::kDrop
                                   ? "blocked because drop rule matched"
                                   : "logged because alert/pass rule matched";
    out << ts.str() << " [**] [1:" << rule.sid
        << ":1] " << rule.msg << " [**] [Classification: " << verdict_text
        << "] [Priority: 1] [Action: " << action_text << "] [Reason: " << reason << "] {"
        << proto << "} " << src << ':' << packet.src_port << " -> " << dst << ':'
        << packet.dst_port << '\n';
  }
}

std::string AlertFast::format_ip(uint32_t ip) const {
  in_addr addr{};
  addr.s_addr = htonl(ip);
  char buf[INET_ADDRSTRLEN] = {0};
  if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
    return "0.0.0.0";
  }
  return buf;
}

std::string AlertFast::format_proto(const core::Packet& packet) const {
  if (packet.is_tcp) {
    return "TCP";
  }
  if (packet.is_udp) {
    return "UDP";
  }
  if (packet.is_icmp) {
    return "ICMP";
  }
  if (packet.is_ipv4) {
    return "IP";
  }
  return "UNKNOWN";
}

}  // namespace minisnort::logger
