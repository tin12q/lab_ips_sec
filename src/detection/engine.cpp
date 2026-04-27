#include "detection/engine.h"

namespace minisnort::detection {
namespace {

rules::Proto proto_from_packet(const core::Packet& packet) {
  if (packet.is_tcp) {
    return rules::Proto::kTcp;
  }
  if (packet.is_udp) {
    return rules::Proto::kUdp;
  }
  if (packet.is_icmp) {
    return rules::Proto::kIcmp;
  }
  return rules::Proto::kIp;
}

}  // namespace

Engine::Engine(const rules::RuleStore& rule_store) : rule_store_(rule_store) {}

Decision Engine::inspect(const core::Packet& packet) {
  Decision decision;
  const flow::FlowSnapshot flow_snapshot = flow_table_.update_and_get(packet);
  const auto proto = proto_from_packet(packet);
  auto candidates = rule_store_.candidates(proto, packet.dst_port);
  if (packet.is_ipv4 && proto != rules::Proto::kIp) {
    const auto ip_candidates = rule_store_.candidates(rules::Proto::kIp, packet.dst_port);
    candidates.insert(candidates.end(), ip_candidates.begin(), ip_candidates.end());
  }

  bool has_drop = false;
  for (const rules::Rule* rule : candidates) {
    if (rule->flow_to_server && !flow_snapshot.to_server) {
      continue;
    }

    if (rule->flow_established && !flow_snapshot.established) {
      continue;
    }

    if (!matcher_.match(*rule, packet)) {
      continue;
    }

    if (!threshold_.allow(*rule, packet)) {
      continue;
    }

    if (rule->action == rules::Action::kPass) {
      decision.matched_sids.clear();
      decision.matched_rules.clear();
      decision.matched_sids.push_back(rule->sid);
      decision.matched_rules.push_back({rule->sid, rule->action, rule->msg});
      decision.verdict = Verdict::kAccept;
      return decision;
    }

    decision.matched_sids.push_back(rule->sid);
    decision.matched_rules.push_back({rule->sid, rule->action, rule->msg});

    if (rule->action == rules::Action::kDrop) {
      has_drop = true;
    }
  }

  if (has_drop) {
    decision.verdict = Verdict::kDrop;
  }
  return decision;
}

}  // namespace minisnort::detection
