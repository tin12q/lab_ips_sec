#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "rules/rule.h"

namespace minisnort::rules {

struct ParseError {
  size_t line = 0;
  std::string message;
};

struct ParseResult {
  std::vector<Rule> rules;
  std::vector<ParseError> errors;

  bool ok() const { return errors.empty(); }
};

class Parser {
 public:
  ParseResult parse_text(const std::string& text,
                         const std::unordered_map<std::string, std::string>& variables) const;
};

}  // namespace minisnort::rules
