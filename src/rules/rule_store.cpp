#include "rules/rule_store.h"

#include <algorithm>

namespace minisnort::rules {
namespace {

bool parse_dst_port(const std::string& token, bool& is_any, uint16_t& out) {
  if (token == "any") {
    is_any = true;
    out = 0;
    return true;
  }

  try {
    size_t parsed = 0;
    const int value = std::stoi(token, &parsed, 10);
    if (parsed != token.size() || value < 0 || value > 65535) {
      return false;
    }
    is_any = false;
    out = static_cast<uint16_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace

void RuleStore::set_rules(std::vector<Rule> rules) {
  rules_ = std::move(rules);
  index_.clear();

  for (size_t i = 0; i < rules_.size(); ++i) {
    bool any_port = true;
    uint16_t dst_port = 0;
    if (!parse_dst_port(rules_[i].dst_port, any_port, dst_port)) {
      any_port = true;
      dst_port = 0;
    }

    index_[BucketKey{rules_[i].proto, any_port, dst_port}].push_back(i);
  }
}

const std::vector<Rule>& RuleStore::rules() const { return rules_; }

std::vector<const Rule*> RuleStore::candidates(Proto proto, uint16_t dst_port) const {
  std::vector<const Rule*> out;

  auto append_bucket = [&](bool any_port, uint16_t port) {
    const auto found = index_.find(BucketKey{proto, any_port, port});
    if (found == index_.end()) {
      return;
    }

    for (size_t idx : found->second) {
      out.push_back(&rules_[idx]);
    }
  };

  append_bucket(false, dst_port);
  append_bucket(true, 0);

  return out;
}

size_t RuleStore::BucketKeyHasher::operator()(const BucketKey& key) const {
  const size_t proto_hash = static_cast<size_t>(key.proto) << 17U;
  const size_t any_port_hash = key.any_port ? 1U : 0U;
  const size_t port_hash = static_cast<size_t>(key.dst_port);
  return proto_hash ^ (any_port_hash << 16U) ^ port_hash;
}

}  // namespace minisnort::rules
