#pragma once

#include <string>

namespace common {

struct UrlParts {
  bool https = false;
  std::string host;
  int port = 0;
  std::string path;
};

// Minimal URL parser for http(s)://host[:port]/path
inline bool parse_url(const std::string& url, UrlParts& out, std::string* err) {
  const std::string http = "http://";
  const std::string https = "https://";
  size_t pos = std::string::npos;
  if (url.rfind(https, 0) == 0) {
    out.https = true;
    pos = https.size();
  } else if (url.rfind(http, 0) == 0) {
    out.https = false;
    pos = http.size();
  } else {
    if (err) *err = "unsupported scheme";
    return false;
  }

  size_t host_end = url.find('/', pos);
  std::string hostport = host_end == std::string::npos ? url.substr(pos) : url.substr(pos, host_end - pos);
  out.path = host_end == std::string::npos ? "/" : url.substr(host_end);

  size_t colon = hostport.find(':');
  if (colon == std::string::npos) {
    out.host = hostport;
    out.port = out.https ? 443 : 80;
  } else {
    out.host = hostport.substr(0, colon);
    std::string port_str = hostport.substr(colon + 1);
    if (port_str.empty()) {
      if (err) *err = "empty port";
      return false;
    }
    try {
      out.port = std::stoi(port_str);
    } catch (...) {
      if (err) *err = "invalid port";
      return false;
    }
  }
  if (out.host.empty()) {
    if (err) *err = "empty host";
    return false;
  }
  return true;
}

} // namespace common
