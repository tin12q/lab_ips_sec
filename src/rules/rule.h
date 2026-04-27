#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace minisnort::rules {

enum class Action {
  kAlert,
  kDrop,
  kPass,
  kLog,
};

enum class Proto {
  kIp,
  kTcp,
  kUdp,
  kIcmp,
};

struct ContentOpt {
  std::string pattern;
  bool nocase = false;
  bool http_uri = false;
};

struct PcreOpt {
  std::string regex;
  bool nocase = false;
};

struct ThresholdOpt {
  enum class Track {
    kBySrc,
    kByDst,
  };

  Track track = Track::kBySrc;
  int count = 0;
  int seconds = 0;
};

struct Rule {
  Action action = Action::kAlert;
  Proto proto = Proto::kIp;

  std::string src_ip;
  std::string dst_ip;
  std::string src_port;
  std::string dst_port;

  std::string msg;
  uint32_t sid = 0;
  uint32_t rev = 1;

  std::vector<ContentOpt> contents;
  std::optional<PcreOpt> pcre;
  std::optional<uint8_t> tcp_flags_required;
  std::optional<uint8_t> icmp_type;
  std::optional<ThresholdOpt> threshold;

  bool flow_to_server = false;
  bool flow_established = false;
};

}  // namespace minisnort::rules
