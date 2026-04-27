#include <fstream>
#include <string>
#include <catch2/catch_test_macros.hpp>

#include "core/packet.h"
#include "detection/engine.h"
#include "logger/alert_fast.h"
#include "rules/rule.h"

namespace minisnort::logger {
namespace {

std::string read_file(const std::string& path) {
  std::ifstream in(path);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

TEST_CASE("alert fast includes threat details and block reason", "[alert_fast]") {
  const std::string path = "/tmp/minisnort_alert_fast_test.log";
  std::ofstream clear(path, std::ios::trunc);
  clear.close();

  core::Packet packet{};
  packet.is_ipv4 = true;
  packet.is_tcp = true;
  packet.src_ip = 0x0A000001;
  packet.dst_ip = 0x0A000002;
  packet.src_port = 49152;
  packet.dst_port = 80;

  AlertFast alert(path);
  alert.emit(packet, detection::Verdict::kDrop,
             {{1000006, rules::Action::kDrop, "Block admin URL"}});

  const std::string line = read_file(path);
  REQUIRE(line.find("[1:1000006:1] Block admin URL") != std::string::npos);
  REQUIRE(line.find("[Classification: drop]") != std::string::npos);
  REQUIRE(line.find("[Action: drop]") != std::string::npos);
  REQUIRE(line.find("[Reason: blocked because drop rule matched]") != std::string::npos);
  REQUIRE(line.find("{TCP} 10.0.0.1:49152 -> 10.0.0.2:80") != std::string::npos);
}

}  // namespace minisnort::logger
