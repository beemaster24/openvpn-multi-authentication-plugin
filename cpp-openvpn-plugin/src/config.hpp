#pragma once

#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace ovpnauth {

struct AuthServiceConfig {
  std::string name;
  std::string url;
  std::string api_key;
  std::string monitoring_path;
  std::string monitoring_api_key;
};

struct LogConfig {
  std::string file;
  std::string level;
};

struct PluginConfig {
  bool verify_cert = true;
  std::vector<AuthServiceConfig> auth_services;
  LogConfig log;
  int connect_timeout_sec = 5;
  int response_timeout_sec = 20;
  bool monitoring_enable = false;
  int check_interval_sec = 5;
};

PluginConfig load_config(const std::string& path);

} // namespace ovpnauth
