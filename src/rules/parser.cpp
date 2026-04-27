#include "rules/parser.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace minisnort::rules {
namespace {

std::string trim(const std::string& value) {
  size_t first = 0;
  while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
    ++first;
  }

  size_t last = value.size();
  while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) {
    --last;
  }

  return value.substr(first, last - first);
}

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool starts_with(const std::string& value, const std::string& prefix) {
  return value.rfind(prefix, 0) == 0;
}

bool parse_uint32(const std::string& value, uint32_t& out) {
  try {
    size_t parsed = 0;
    const unsigned long v = std::stoul(value, &parsed, 10);
    if (parsed != value.size() || v > static_cast<unsigned long>(std::numeric_limits<uint32_t>::max())) {
      return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
  } catch (...) {
    return false;
  }
}

bool parse_int(const std::string& value, int& out) {
  try {
    size_t parsed = 0;
    const int v = std::stoi(value, &parsed, 10);
    if (parsed != value.size()) {
      return false;
    }
    out = v;
    return true;
  } catch (...) {
    return false;
  }
}

bool parse_action(const std::string& raw, Action& out) {
  const auto value = to_lower(raw);
  if (value == "alert") {
    out = Action::kAlert;
    return true;
  }
  if (value == "drop") {
    out = Action::kDrop;
    return true;
  }
  if (value == "pass") {
    out = Action::kPass;
    return true;
  }
  if (value == "log") {
    out = Action::kLog;
    return true;
  }
  return false;
}

bool parse_proto(const std::string& raw, Proto& out) {
  const auto value = to_lower(raw);
  if (value == "ip") {
    out = Proto::kIp;
    return true;
  }
  if (value == "tcp") {
    out = Proto::kTcp;
    return true;
  }
  if (value == "udp") {
    out = Proto::kUdp;
    return true;
  }
  if (value == "icmp") {
    out = Proto::kIcmp;
    return true;
  }
  return false;
}

bool is_valid_port_token(const std::string& token, bool allow_variable) {
  if (token == "any") {
    return true;
  }

  if (allow_variable && !token.empty() && token[0] == '$') {
    return true;
  }

  try {
    size_t parsed = 0;
    const int value = std::stoi(token, &parsed, 10);
    return parsed == token.size() && value >= 0 && value <= 65535;
  } catch (...) {
    return false;
  }
}

std::string resolve_variable(const std::string& token,
                             const std::unordered_map<std::string, std::string>& variables) {
  if (token.empty() || token[0] != '$') {
    return token;
  }

  const std::string name = token.substr(1);
  const auto found = variables.find(name);
  if (found != variables.end()) {
    return found->second;
  }

  if (name == "HOME_NET") {
    return "10.201.0.0/24";
  }

  return token;
}

bool parse_header(const std::string& header, Rule& rule, std::string& error) {
  std::istringstream iss(header);
  std::string action;
  std::string proto;
  std::string src_ip;
  std::string src_port;
  std::string arrow;
  std::string dst_ip;
  std::string dst_port;

  if (!(iss >> action >> proto >> src_ip >> src_port >> arrow >> dst_ip >> dst_port)) {
    error = "invalid rule header format";
    return false;
  }

  std::string trailing;
  if (iss >> trailing) {
    error = "unexpected token in rule header: " + trailing;
    return false;
  }

  if (arrow != "->") {
    error = "rule header must contain '->'";
    return false;
  }

  if (!parse_action(action, rule.action)) {
    error = "unsupported action: " + action;
    return false;
  }

  if (!parse_proto(proto, rule.proto)) {
    error = "unsupported protocol: " + proto;
    return false;
  }

  if (!is_valid_port_token(src_port, true)) {
    error = "invalid source port token: " + src_port;
    return false;
  }

  if (!is_valid_port_token(dst_port, true)) {
    error = "invalid destination port token: " + dst_port;
    return false;
  }

  rule.src_ip = src_ip;
  rule.src_port = src_port;
  rule.dst_ip = dst_ip;
  rule.dst_port = dst_port;

  return true;
}

bool parse_quoted_string(const std::string& value, std::string& out) {
  const std::string v = trim(value);
  if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
    return false;
  }
  out = v.substr(1, v.size() - 2);
  return true;
}

bool parse_pcre(const std::string& value, PcreOpt& out) {
  std::string inner;
  if (!parse_quoted_string(value, inner)) {
    return false;
  }

  if (inner.size() < 2 || inner.front() != '/') {
    return false;
  }

  const size_t last_slash = inner.find_last_of('/');
  if (last_slash == std::string::npos || last_slash == 0) {
    return false;
  }

  out.regex = inner.substr(1, last_slash - 1);
  const std::string flags = inner.substr(last_slash + 1);
  out.nocase = flags.find('i') != std::string::npos;
  return !out.regex.empty();
}

bool parse_tcp_flags(const std::string& value, uint8_t& out) {
  const auto v = trim(value);
  if (v.empty()) {
    return false;
  }

  uint8_t flags = 0;
  for (char c : v) {
    switch (c) {
      case 'S':
        flags = static_cast<uint8_t>(flags | 0x02);
        break;
      case 'A':
        flags = static_cast<uint8_t>(flags | 0x10);
        break;
      case 'F':
        flags = static_cast<uint8_t>(flags | 0x01);
        break;
      case 'R':
        flags = static_cast<uint8_t>(flags | 0x04);
        break;
      case 'P':
        flags = static_cast<uint8_t>(flags | 0x08);
        break;
      case 'U':
        flags = static_cast<uint8_t>(flags | 0x20);
        break;
      default:
        return false;
    }
  }

  out = flags;
  return true;
}

bool parse_threshold(const std::string& value, ThresholdOpt& out) {
  const auto normalized = trim(value);
  std::stringstream ss(normalized);
  std::string segment;

  while (std::getline(ss, segment, ',')) {
    const std::string item = trim(segment);
    if (item.empty()) {
      continue;
    }

    if (item == "type threshold") {
      continue;
    }

    if (starts_with(item, "track ")) {
      const std::string track = trim(item.substr(6));
      if (track == "by_src") {
        out.track = ThresholdOpt::Track::kBySrc;
      } else if (track == "by_dst") {
        out.track = ThresholdOpt::Track::kByDst;
      } else {
        return false;
      }
    } else if (starts_with(item, "count ")) {
      if (!parse_int(trim(item.substr(6)), out.count)) {
        return false;
      }
    } else if (starts_with(item, "seconds ")) {
      if (!parse_int(trim(item.substr(8)), out.seconds)) {
        return false;
      }
    } else {
      return false;
    }
  }

  return out.count > 0 && out.seconds > 0;
}

bool parse_option(const std::string& key, const std::string& value, Rule& rule, std::string& error) {
  if (key == "msg") {
    if (!parse_quoted_string(value, rule.msg)) {
      error = "msg must be a quoted string";
      return false;
    }
    return true;
  }

  if (key == "sid") {
    if (!parse_uint32(trim(value), rule.sid) || rule.sid == 0) {
      error = "sid must be a positive integer";
      return false;
    }
    return true;
  }

  if (key == "rev") {
    if (!parse_uint32(trim(value), rule.rev) || rule.rev == 0) {
      error = "rev must be a positive integer";
      return false;
    }
    return true;
  }

  if (key == "content") {
    ContentOpt opt;
    if (!parse_quoted_string(value, opt.pattern)) {
      error = "content must be a quoted string";
      return false;
    }
    rule.contents.push_back(opt);
    return true;
  }

  if (key == "pcre") {
    PcreOpt pcre;
    if (!parse_pcre(value, pcre)) {
      error = "pcre must follow format \"/.../i\"";
      return false;
    }
    rule.pcre = pcre;
    return true;
  }

  if (key == "flags") {
    uint8_t flags = 0;
    if (!parse_tcp_flags(value, flags)) {
      error = "flags contains unsupported symbols";
      return false;
    }
    rule.tcp_flags_required = flags;
    return true;
  }

  if (key == "itype") {
    uint32_t type = 0;
    if (!parse_uint32(trim(value), type) || type > 255) {
      error = "itype must be in [0,255]";
      return false;
    }
    rule.icmp_type = static_cast<uint8_t>(type);
    return true;
  }

  if (key == "flow") {
    std::stringstream ss(value);
    std::string token;
    while (std::getline(ss, token, ',')) {
      const std::string v = trim(token);
      if (v == "to_server") {
        rule.flow_to_server = true;
      } else if (v == "established") {
        rule.flow_established = true;
      } else {
        error = "unsupported flow option: " + v;
        return false;
      }
    }
    return true;
  }

  if (key == "threshold") {
    ThresholdOpt threshold;
    if (!parse_threshold(value, threshold)) {
      error = "invalid threshold expression";
      return false;
    }
    rule.threshold = threshold;
    return true;
  }

  error = "unsupported option key: " + key;
  return false;
}

enum class LastOption {
  kNone,
  kContent,
  kPcre,
};

bool apply_keyword(const std::string& keyword, Rule& rule, LastOption last_option, std::string& error) {
  if (keyword == "nocase") {
    if (rule.contents.empty()) {
      error = "nocase requires previous content";
      return false;
    }
    rule.contents.back().nocase = true;
    return true;
  }

  if (keyword == "http_uri" || keyword == "http_header" || keyword == "http_method" ||
      keyword == "http_client_body") {
    HttpBuffer buffer = HttpBuffer::kClientBody;
    if (keyword == "http_uri") {
      buffer = HttpBuffer::kUri;
    } else if (keyword == "http_header") {
      buffer = HttpBuffer::kHeader;
    } else if (keyword == "http_method") {
      buffer = HttpBuffer::kMethod;
    }

    if (last_option == LastOption::kContent && !rule.contents.empty()) {
      rule.contents.back().http_buffer = buffer;
      return true;
    }
    if (last_option == LastOption::kPcre && rule.pcre.has_value()) {
      rule.pcre->http_buffer = buffer;
      return true;
    }

    error = keyword + " requires previous content or pcre";
    return false;
  }

  error = "unsupported keyword option: " + keyword;
  return false;
}

std::vector<std::string> split_options(const std::string& options, std::string& error) {
  std::vector<std::string> tokens;
  std::string current;
  bool in_quotes = false;
  bool escaped = false;

  for (char c : options) {
    if (escaped) {
      current.push_back(c);
      escaped = false;
      continue;
    }

    if (c == '\\') {
      current.push_back(c);
      escaped = true;
      continue;
    }

    if (c == '"') {
      in_quotes = !in_quotes;
      current.push_back(c);
      continue;
    }

    if (c == ';' && !in_quotes) {
      const std::string token = trim(current);
      if (!token.empty()) {
        tokens.push_back(token);
      }
      current.clear();
      continue;
    }

    current.push_back(c);
  }

  if (in_quotes) {
    error = "unterminated quoted string in options";
    return {};
  }

  if (!trim(current).empty()) {
    error = "missing ';' in options";
    return {};
  }

  return tokens;
}

bool parse_options(const std::string& options, Rule& rule, std::string& error) {
  const std::vector<std::string> tokens = split_options(options, error);
  if (!error.empty()) {
    return false;
  }

  LastOption last_option = LastOption::kNone;
  for (const std::string& raw_token : tokens) {
    const size_t sep = raw_token.find(':');
    if (sep == std::string::npos) {
      if (!apply_keyword(raw_token, rule, last_option, error)) {
        return false;
      }
      continue;
    }

    const std::string key = trim(raw_token.substr(0, sep));
    const std::string value = trim(raw_token.substr(sep + 1));
    if (key.empty() || value.empty()) {
      error = "invalid option token: " + raw_token;
      return false;
    }

    if (!parse_option(key, value, rule, error)) {
      return false;
    }
    if (key == "content") {
      last_option = LastOption::kContent;
    } else if (key == "pcre") {
      last_option = LastOption::kPcre;
    } else {
      last_option = LastOption::kNone;
    }
  }

  if (rule.sid == 0) {
    error = "sid is required";
    return false;
  }

  if (rule.msg.empty()) {
    error = "msg is required";
    return false;
  }

  return true;
}

}  // namespace

ParseResult Parser::parse_text(
    const std::string& text, const std::unordered_map<std::string, std::string>& variables) const {
  ParseResult result;
  std::istringstream lines(text);
  std::string line;
  size_t line_no = 0;

  while (std::getline(lines, line)) {
    ++line_no;
    const std::string trimmed = trim(line);
    if (trimmed.empty() || starts_with(trimmed, "#")) {
      continue;
    }

    const size_t lparen = trimmed.find('(');
    const size_t rparen = trimmed.find_last_of(')');
    if (lparen == std::string::npos || rparen == std::string::npos || rparen <= lparen) {
      result.errors.push_back({line_no, "rule must contain options enclosed by parentheses"});
      break;
    }

    Rule rule;
    std::string header_error;
    const std::string header = trim(trimmed.substr(0, lparen));
    if (!parse_header(header, rule, header_error)) {
      result.errors.push_back({line_no, header_error});
      break;
    }

    rule.src_ip = resolve_variable(rule.src_ip, variables);
    rule.src_port = resolve_variable(rule.src_port, variables);
    rule.dst_ip = resolve_variable(rule.dst_ip, variables);
    rule.dst_port = resolve_variable(rule.dst_port, variables);

    if (!is_valid_port_token(rule.src_port, false)) {
      result.errors.push_back({line_no, "invalid resolved source port token: " + rule.src_port});
      break;
    }

    if (!is_valid_port_token(rule.dst_port, false)) {
      result.errors.push_back({line_no, "invalid resolved destination port token: " + rule.dst_port});
      break;
    }

    if (!trim(trimmed.substr(rparen + 1)).empty()) {
      result.errors.push_back({line_no, "unexpected trailing text after rule options"});
      break;
    }

    const std::string option_text = trimmed.substr(lparen + 1, rparen - lparen - 1);
    std::string option_error;
    if (!parse_options(option_text, rule, option_error)) {
      result.errors.push_back({line_no, option_error});
      break;
    }

    result.rules.push_back(std::move(rule));
  }

  return result;
}

}  // namespace minisnort::rules
