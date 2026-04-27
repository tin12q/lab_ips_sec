#include "detection/http_parser.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <sstream>

namespace minisnort::detection {
namespace {

std::string url_decode_once(const std::string& value) {
  std::string out;
  out.reserve(value.size());

  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size() &&
        std::isxdigit(static_cast<unsigned char>(value[i + 1])) &&
        std::isxdigit(static_cast<unsigned char>(value[i + 2]))) {
      const std::string hex = value.substr(i + 1, 2);
      out.push_back(static_cast<char>(std::stoi(hex, nullptr, 16)));
      i += 2;
      continue;
    }
    out.push_back(value[i] == '+' ? ' ' : value[i]);
  }

  return out;
}

std::string canonicalize_path(const std::string& value) {
  const size_t query = value.find('?');
  std::string path = query == std::string::npos ? value : value.substr(0, query);
  const std::string suffix = query == std::string::npos ? "" : value.substr(query);
  std::replace(path.begin(), path.end(), '\\', '/');

  std::vector<std::string> parts;
  std::stringstream ss(path);
  std::string part;
  while (std::getline(ss, part, '/')) {
    if (part.empty() || part == ".") {
      continue;
    }
    if (part == "..") {
      if (!parts.empty()) {
        parts.pop_back();
      }
      continue;
    }
    parts.push_back(part);
  }

  std::string out = "/";
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) {
      out.push_back('/');
    }
    out += parts[i];
  }
  return out + suffix;
}

std::string decode_uri(const std::string& uri) {
  constexpr int kMaxDecodePasses = 8;
  std::string decoded = uri;
  for (int i = 0; i < kMaxDecodePasses; ++i) {
    std::string next = url_decode_once(decoded);
    std::replace(next.begin(), next.end(), '\\', '/');
    if (next == decoded) {
      break;
    }
    decoded = next;
  }
  return decoded;
}

std::string normalize_uri(const std::string& uri) {
  return canonicalize_path(decode_uri(uri));
}

size_t find_header_end(const std::string& payload, size_t start) {
  if (start < payload.size()) {
    if (payload.compare(start, 2, "\r\n") == 0 || payload[start] == '\n') {
      return start;
    }
  }

  const size_t crlf = payload.find("\r\n\r\n", start);
  const size_t lf = payload.find("\n\n", start);
  if (crlf == std::string::npos) {
    return lf;
  }
  if (lf == std::string::npos) {
    return crlf;
  }
  return std::min(crlf, lf);
}

size_t header_delimiter_size(const std::string& payload, size_t pos) {
  if (payload.compare(pos, 4, "\r\n\r\n") == 0) {
    return 4;
  }
  if (payload.compare(pos, 2, "\r\n") == 0 || payload.compare(pos, 2, "\n\n") == 0) {
    return 2;
  }
  return 1;
}

std::string trim(std::string value) {
  const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  });
  const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }).base();
  if (begin >= end) {
    return "";
  }
  return std::string(begin, end);
}

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool has_chunked_transfer_encoding(const std::string& headers) {
  std::stringstream ss(headers);
  std::string line;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::string lower = to_lower(line);
    constexpr char kPrefix[] = "transfer-encoding:";
    if (lower.rfind(kPrefix, 0) == 0 && lower.find("chunked", sizeof(kPrefix) - 1) != std::string::npos) {
      return true;
    }
  }
  return false;
}

std::optional<size_t> parse_size(const std::string& value, int base) {
  const std::string trimmed = trim(value);
  size_t out = 0;
  const char* begin = trimmed.data();
  const char* end = begin + trimmed.size();
  const auto result = std::from_chars(begin, end, out, base);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::nullopt;
  }
  return out;
}

std::optional<size_t> content_length(const std::string& headers) {
  std::optional<size_t> length;
  std::stringstream ss(headers);
  std::string line;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::string lower = to_lower(line);
    constexpr char kPrefix[] = "content-length:";
    if (lower.rfind(kPrefix, 0) == 0) {
      const std::optional<size_t> parsed = parse_size(line.substr(sizeof(kPrefix) - 1), 10);
      if (!parsed.has_value()) {
        return std::nullopt;
      }
      if (length.has_value() && length.value() != parsed.value()) {
        return std::nullopt;
      }
      length = parsed.value();
    }
  }
  return length.value_or(0);
}

std::optional<size_t> find_chunk_line_end(const std::string& payload, size_t start) {
  const size_t line_end = payload.find('\n', start);
  if (line_end == std::string::npos) {
    return std::nullopt;
  }
  return line_end;
}

std::optional<size_t> chunk_size(const std::string& line) {
  std::string value = line;
  if (!value.empty() && value.back() == '\r') {
    value.pop_back();
  }
  const size_t extension = value.find(';');
  if (extension != std::string::npos) {
    value = value.substr(0, extension);
  }
  return parse_size(value, 16);
}

std::optional<std::pair<std::string, size_t>> decode_chunked_body(const std::string& payload, size_t body_start) {
  std::string body;
  size_t offset = body_start;

  while (offset < payload.size()) {
    const std::optional<size_t> line_end = find_chunk_line_end(payload, offset);
    if (!line_end.has_value()) {
      return std::nullopt;
    }

    std::string size_line = payload.substr(offset, line_end.value() - offset);
    const std::optional<size_t> size = chunk_size(size_line);
    if (!size.has_value()) {
      return std::nullopt;
    }

    size_t chunk_start = line_end.value() + 1;
    if (chunk_start > payload.size()) {
      return std::nullopt;
    }

    if (size.value() == 0) {
      offset = chunk_start;
      while (offset < payload.size()) {
        const std::optional<size_t> trailer_line_end = find_chunk_line_end(payload, offset);
        if (!trailer_line_end.has_value()) {
          return std::nullopt;
        }
        std::string trailer_line = payload.substr(offset, trailer_line_end.value() - offset);
        if (!trailer_line.empty() && trailer_line.back() == '\r') {
          trailer_line.pop_back();
        }
        offset = trailer_line_end.value() + 1;
        if (trailer_line.empty()) {
          return std::make_pair(body, offset);
        }
      }
      return std::nullopt;
    }

    if (size.value() > payload.size() - chunk_start) {
      return std::nullopt;
    }
    body += payload.substr(chunk_start, size.value());
    offset = chunk_start + size.value();

    if (offset >= payload.size()) {
      return std::nullopt;
    }
    if (payload.compare(offset, 2, "\r\n") == 0) {
      offset += 2;
    } else if (payload[offset] == '\n') {
      offset += 1;
    } else {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

std::optional<HttpBuffers> parse_one_request(const std::string& payload, size_t start, size_t& next) {
  const size_t line_end = payload.find('\n', start);
  if (line_end == std::string::npos) {
    return std::nullopt;
  }

  std::string request_line = payload.substr(start, line_end - start);
  if (!request_line.empty() && request_line.back() == '\r') {
    request_line.pop_back();
  }

  const size_t method_end = request_line.find(' ');
  if (method_end == std::string::npos || method_end == 0) {
    return std::nullopt;
  }

  const size_t uri_end = request_line.find(' ', method_end + 1);
  if (uri_end == std::string::npos || uri_end <= method_end + 1) {
    return std::nullopt;
  }

  const std::string method = request_line.substr(0, method_end);
  for (char c : method) {
    if (!std::isupper(static_cast<unsigned char>(c))) {
      return std::nullopt;
    }
  }

  const std::string version = request_line.substr(uri_end + 1);
  if (version.rfind("HTTP/", 0) != 0) {
    return std::nullopt;
  }

  size_t headers_end = find_header_end(payload, line_end + 1);
  size_t delimiter_size = 0;
  if (line_end + 1 < payload.size() && payload[line_end + 1] == '\r' &&
      line_end + 2 < payload.size() && payload[line_end + 2] == '\n') {
    headers_end = line_end + 1;
    delimiter_size = 2;
  } else if (line_end + 1 < payload.size() && payload[line_end + 1] == '\n') {
    headers_end = line_end + 1;
    delimiter_size = 1;
  } else if (headers_end != std::string::npos) {
    delimiter_size = header_delimiter_size(payload, headers_end);
  } else {
    return std::nullopt;
  }

  const size_t body_start = headers_end + delimiter_size;
  if (body_start > payload.size()) {
    return std::nullopt;
  }

  const std::string headers = payload.substr(line_end + 1, headers_end - (line_end + 1));
  std::string client_body;

  if (has_chunked_transfer_encoding(headers)) {
    const std::optional<std::pair<std::string, size_t>> decoded = decode_chunked_body(payload, body_start);
    if (!decoded.has_value()) {
      return std::nullopt;
    }
    client_body = decoded.value().first;
    next = decoded.value().second;
  } else {
    const std::optional<size_t> len = content_length(headers);
    if (!len.has_value() || len.value() > payload.size() - body_start) {
      return std::nullopt;
    }
    client_body = payload.substr(body_start, len.value());
    next = body_start + len.value();
  }

  if (next <= start) {
    return std::nullopt;
  }

  const std::string uri = request_line.substr(method_end + 1, uri_end - (method_end + 1));

  HttpBuffers buffers;
  buffers.method = method;
  buffers.uri = normalize_uri(uri);
  buffers.decoded_uri = decode_uri(uri);
  buffers.headers = headers;
  buffers.client_body = client_body;
  return buffers;
}

}  // namespace

std::optional<std::string> HttpParser::extract_uri(const std::string& payload) const {
  const std::vector<HttpBuffers> requests = parse_requests(payload);
  if (requests.empty()) {
    return std::nullopt;
  }
  return requests.front().uri;
}

std::vector<HttpBuffers> HttpParser::parse_requests(const std::string& payload) const {
  std::vector<HttpBuffers> requests;
  size_t offset = 0;

  while (offset < payload.size()) {
    size_t next = offset;
    const std::optional<HttpBuffers> request = parse_one_request(payload, offset, next);
    if (!request.has_value()) {
      break;
    }
    requests.push_back(request.value());
    offset = next;
  }

  return requests;
}

}  // namespace minisnort::detection
