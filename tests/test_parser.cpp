#include <fstream>
#include <string>
#include <unordered_map>

#include <catch2/catch_test_macros.hpp>

#include "rules/parser.h"
#include "rules/rule_store.h"
#include "util/config.h"

namespace {

std::unordered_map<std::string, std::string> default_vars() {
  return {{"HOME_NET", "10.201.0.0/24"}};
}

const char* valid_rules_text() {
  return R"(
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; itype:8; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"TCP SYN Scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 30; sid:1000003; rev:1;)
drop tcp any any -> $HOME_NET 80 (msg:"SQLi UNION SELECT"; content:"UNION"; nocase; content:"SELECT"; nocase; pcre:"/union\s+select/i"; sid:1000004; rev:1;)
drop icmp any any -> $HOME_NET any (msg:"Block all ICMP"; sid:1000005; rev:1;)
drop tcp any any -> $HOME_NET 80 (msg:"Block admin URL"; content:"/admin"; http_uri; sid:1000006; rev:1;)
)";
}

bool write_temp_file(const std::string& filename, const std::string& content, std::string& path_out) {
  const std::string path = "/tmp/" + filename;
  std::ofstream out(path);
  if (!out) {
    return false;
  }
  out << content;
  path_out = path;
  return true;
}

}  // namespace

TEST_CASE("parser accepts six demo rules") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(valid_rules_text(), default_vars());

  REQUIRE(result.ok());
  REQUIRE(result.rules.size() == 6);
  REQUIRE(result.rules[0].sid == 1000001);
  REQUIRE(result.rules[0].dst_ip == "10.201.0.0/24");
  REQUIRE(result.rules[3].contents.size() == 2);
  REQUIRE(result.rules[3].contents[0].nocase);
  REQUIRE(result.rules[5].contents[0].http_buffer == minisnort::rules::HttpBuffer::kUri);
}

TEST_CASE("parser accepts Sprint 7 HTTP buffer keywords") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(
      "drop tcp any any -> $HOME_NET 80 (msg:\"SQLi in body\"; content:\"UNION\"; nocase; http_client_body; sid:1000008; rev:1;)\n"
      "drop tcp any any -> $HOME_NET 80 (msg:\"Suspicious User-Agent\"; content:\"sqlmap\"; nocase; http_header; sid:1000009; rev:1;)\n"
      "drop tcp any any -> $HOME_NET 80 (msg:\"POST method\"; content:\"POST\"; http_method; sid:1000010; rev:1;)\n"
      "drop tcp any any -> $HOME_NET 80 (msg:\"Body PCRE\"; pcre:\"/union\\s+select/i\"; http_client_body; sid:1000011; rev:1;)\n"
      "drop tcp any any -> $HOME_NET 80 (msg:\"Mixed Body PCRE\"; content:\"UNION\"; nocase; pcre:\"/union\\s+select/i\"; http_client_body; sid:1000012; rev:1;)\n"
      "drop tcp any any -> $HOME_NET 80 (msg:\"Shipped Body SQLi\"; content:\"UNION\"; nocase; http_client_body; pcre:\"/union\\s+select/i\"; http_client_body; sid:1000013; rev:1;)",
      default_vars());

  REQUIRE(result.ok());
  REQUIRE(result.rules[0].contents[0].http_buffer == minisnort::rules::HttpBuffer::kClientBody);
  REQUIRE(result.rules[1].contents[0].http_buffer == minisnort::rules::HttpBuffer::kHeader);
  REQUIRE(result.rules[2].contents[0].http_buffer == minisnort::rules::HttpBuffer::kMethod);
  REQUIRE(result.rules[3].pcre->http_buffer == minisnort::rules::HttpBuffer::kClientBody);
  REQUIRE(result.rules[4].contents[0].http_buffer == minisnort::rules::HttpBuffer::kPayload);
  REQUIRE(result.rules[4].pcre->http_buffer == minisnort::rules::HttpBuffer::kClientBody);
  REQUIRE(result.rules[5].contents[0].http_buffer == minisnort::rules::HttpBuffer::kClientBody);
  REQUIRE(result.rules[5].pcre->http_buffer == minisnort::rules::HttpBuffer::kClientBody);
}

TEST_CASE("parser reports malformed rule") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text("alert tcp any any -> any 80 msg:\"x\"; sid:1;", default_vars());

  REQUIRE_FALSE(result.ok());
  REQUIRE(result.errors.front().line == 1);
}

TEST_CASE("parser rejects sid overflow") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(
      "alert tcp any any -> any 80 (msg:\"x\"; sid:4294967296; rev:1;)", default_vars());

  REQUIRE_FALSE(result.ok());
}

TEST_CASE("parser handles semicolon inside quoted values") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(
      "alert tcp any any -> any 80 (msg:\"x;y\"; content:\"a;b\"; sid:1; rev:1;)",
      default_vars());

  REQUIRE(result.ok());
  REQUIRE(result.rules[0].msg == "x;y");
  REQUIRE(result.rules[0].contents[0].pattern == "a;b");
}

TEST_CASE("parser rejects unknown threshold token") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(
      "alert tcp any any -> any 80 (msg:\"x\"; threshold:type threshold, track by_src, foo bar, count 1, seconds 1; sid:1; rev:1;)",
      default_vars());

  REQUIRE_FALSE(result.ok());
}

TEST_CASE("parser rejects trailing text after closing parenthesis") {
  minisnort::rules::Parser parser;
  auto result = parser.parse_text(
      "alert tcp any any -> any 80 (msg:\"x\"; sid:1; rev:1;) trailing", default_vars());

  REQUIRE_FALSE(result.ok());
}

TEST_CASE("parser resolves port variables before validation") {
  minisnort::rules::Parser parser;
  auto vars = default_vars();
  vars["HTTP_PORT"] = "80";

  auto result = parser.parse_text(
      "alert tcp any any -> $HOME_NET $HTTP_PORT (msg:\"x\"; sid:1; rev:1;)", vars);

  REQUIRE(result.ok());
  REQUIRE(result.rules.size() == 1);
  REQUIRE(result.rules[0].dst_port == "80");
}

TEST_CASE("parser rejects port variables that resolve to invalid ports") {
  minisnort::rules::Parser parser;
  auto vars = default_vars();
  vars["BAD_PORT"] = "99999";

  auto result = parser.parse_text(
      "alert tcp any any -> $HOME_NET $BAD_PORT (msg:\"x\"; sid:1; rev:1;)", vars);

  REQUIRE_FALSE(result.ok());
}

TEST_CASE("rule store returns exact then any candidates") {
  minisnort::rules::Rule exact_rule;
  exact_rule.proto = minisnort::rules::Proto::kTcp;
  exact_rule.dst_port = "80";
  exact_rule.sid = 10;

  minisnort::rules::Rule any_rule;
  any_rule.proto = minisnort::rules::Proto::kTcp;
  any_rule.dst_port = "any";
  any_rule.sid = 11;

  minisnort::rules::RuleStore store;
  store.set_rules({any_rule, exact_rule});

  const auto candidates = store.candidates(minisnort::rules::Proto::kTcp, 80);
  REQUIRE(candidates.size() == 2);
  REQUIRE(candidates[0]->sid == 10);
  REQUIRE(candidates[1]->sid == 11);
}

TEST_CASE("rule store ignores rules from other protocols") {
  minisnort::rules::Rule udp_rule;
  udp_rule.proto = minisnort::rules::Proto::kUdp;
  udp_rule.dst_port = "53";
  udp_rule.sid = 20;

  minisnort::rules::RuleStore store;
  store.set_rules({udp_rule});

  const auto candidates = store.candidates(minisnort::rules::Proto::kTcp, 53);
  REQUIRE(candidates.empty());
}

TEST_CASE("rule store treats invalid dst_port token as any") {
  minisnort::rules::Rule bad_port_rule;
  bad_port_rule.proto = minisnort::rules::Proto::kTcp;
  bad_port_rule.dst_port = "80:90";
  bad_port_rule.sid = 30;

  minisnort::rules::RuleStore store;
  store.set_rules({bad_port_rule});

  const auto candidates = store.candidates(minisnort::rules::Proto::kTcp, 443);
  REQUIRE(candidates.size() == 1);
  REQUIRE(candidates[0]->sid == 30);
}

TEST_CASE("config loader reads known keys") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-basic.yaml",
                          "networks:\n"
                          "  home_net: \"10.1.0.0/16\"\n"
                          "rules:\n"
                          "  file: \"custom.rules\"\n"
                          "logging:\n"
                          "  alert_file: \"/tmp/minisnort-alert.log\"\n"
                          "  level: warn\n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE(ok);
  REQUIRE(config.home_net == "10.1.0.0/16");
  REQUIRE(config.rules_file == "custom.rules");
  REQUIRE(config.alert_file == "/tmp/minisnort-alert.log");
  REQUIRE(config.log_level == "warn");
}

TEST_CASE("config loader trims values") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-trimmed.yaml",
                          "networks:\n"
                          "  home_net:   \"172.16.0.0/12\"   \n"
                          "rules:\n"
                          "  file:   test.rules   \n"
                          "logging:\n"
                          "  alert_file:   /tmp/alerts.log   \n"
                          "  level:   info   \n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE(ok);
  REQUIRE(config.home_net == "172.16.0.0/12");
  REQUIRE(config.rules_file == "test.rules");
  REQUIRE(config.alert_file == "/tmp/alerts.log");
  REQUIRE(config.log_level == "info");
}

TEST_CASE("config loader rejects unknown top-level section") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-empty-sections.yaml", "other:\n  value: 1\n", path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE_FALSE(ok);
  REQUIRE_FALSE(error.empty());
}

TEST_CASE("config loader rejects invalid logging level") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-bad-level.yaml",
                          "networks:\n"
                          "  home_net: \"10.1.0.0/16\"\n"
                          "rules:\n"
                          "  file: \"custom.rules\"\n"
                          "logging:\n"
                          "  alert_file: \"/tmp/minisnort-alert.log\"\n"
                          "  level: noisy\n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE_FALSE(ok);
  REQUIRE(error.find("logging.level invalid") != std::string::npos);
}

TEST_CASE("config loader rejects relative alert file path") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-relative-alert.yaml",
                          "networks:\n"
                          "  home_net: \"10.1.0.0/16\"\n"
                          "rules:\n"
                          "  file: \"custom.rules\"\n"
                          "logging:\n"
                          "  alert_file: \"logs/alert.log\"\n"
                          "  level: info\n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE_FALSE(ok);
  REQUIRE(error.find("must be an absolute path") != std::string::npos);
}

TEST_CASE("config loader rejects alert file path with parent traversal") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-parent-alert.yaml",
                          "networks:\n"
                          "  home_net: \"10.1.0.0/16\"\n"
                          "rules:\n"
                          "  file: \"custom.rules\"\n"
                          "logging:\n"
                          "  alert_file: \"/var/log/minisnort/../shadow\"\n"
                          "  level: info\n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE_FALSE(ok);
  REQUIRE(error.find("cannot contain '..'") != std::string::npos);
}

TEST_CASE("config loader accepts normalized absolute alert file path") {
  std::string path;
  REQUIRE(write_temp_file("minisnort-config-absolute-alert.yaml",
                          "networks:\n"
                          "  home_net: \"10.1.0.0/16\"\n"
                          "rules:\n"
                          "  file: \"custom.rules\"\n"
                          "logging:\n"
                          "  alert_file: \"/var/log/minisnort/alert.log\"\n"
                          "  level: info\n",
                          path));

  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file(path, config, error);

  REQUIRE(ok);
  REQUIRE(config.alert_file == "/var/log/minisnort/alert.log");
}

TEST_CASE("config loader reports missing file") {
  minisnort::util::Config config;
  std::string error;
  const bool ok = minisnort::util::load_config_file("/tmp/does-not-exist-minisnort.yaml", config, error);

  REQUIRE_FALSE(ok);
  REQUIRE_FALSE(error.empty());
}
