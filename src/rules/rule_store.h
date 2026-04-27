#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "rules/rule.h"

namespace minisnort::rules {

class RuleStore {
 public:
  void set_rules(std::vector<Rule> rules);
  const std::vector<Rule>& rules() const;
  std::vector<const Rule*> candidates(Proto proto, uint16_t dst_port) const;

 private:
  struct BucketKey {
    Proto proto;
    bool any_port;
    uint16_t dst_port;

    bool operator==(const BucketKey& other) const {
      return proto == other.proto && any_port == other.any_port && dst_port == other.dst_port;
    }
  };

  struct BucketKeyHasher {
    size_t operator()(const BucketKey& key) const;
  };

  std::vector<Rule> rules_;
  std::unordered_map<BucketKey, std::vector<size_t>, BucketKeyHasher> index_;
};

}  // namespace minisnort::rules
