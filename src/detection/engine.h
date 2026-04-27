#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/packet.h"
#include "detection/matcher.h"
#include "detection/threshold.h"
#include "flow/flow_table.h"
#include "rules/rule_store.h"

namespace minisnort::detection {

enum class Verdict {
  kAccept,
  kDrop,
};

struct MatchedRule {
  uint32_t sid = 0;
  rules::Action action = rules::Action::kAlert;
  std::string msg;
};

struct Decision {
  Verdict verdict = Verdict::kAccept;
  std::vector<uint32_t> matched_sids;
  std::vector<MatchedRule> matched_rules;
};

class Engine {
 public:
  explicit Engine(const rules::RuleStore& rule_store);

  Decision inspect(const core::Packet& packet);

 private:
  const rules::RuleStore& rule_store_;
  Matcher matcher_{};
  Threshold threshold_{};
  flow::FlowTable flow_table_{};
};

}  // namespace minisnort::detection
