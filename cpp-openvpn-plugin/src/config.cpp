#include "config.hpp"

#include <stdexcept>

namespace ovpnauth {

static std::string get_string(const YAML::Node& n, const std::string& key, bool required = true) {
  auto v = n[key];
  if (!v) {
    if (required) throw std::runtime_error("missing key: " + key);
    return "";
  }
  return v.as<std::string>();
}

static int get_int(const YAML::Node& n, const std::string& key, bool required = true, int def = 0) {
  auto v = n[key];
  if (!v) {
    if (required) throw std::runtime_error("missing key: " + key);
    return def;
  }
  return v.as<int>();
}

static bool get_bool(const YAML::Node& n, const std::string& key, bool required = true, bool def = false) {
  auto v = n[key];
  if (!v) {
    if (required) throw std::runtime_error("missing key: " + key);
    return def;
  }
  return v.as<bool>();
}

PluginConfig load_config(const std::string& path) {
  auto root = YAML::LoadFile(path);
  PluginConfig cfg;

  cfg.verify_cert = get_bool(root, "https_verify_cert", false, true);

  auto auth_services = root["auth_service"];
  if (!auth_services) throw std::runtime_error("missing auth_service section");
  for (const auto& s : auth_services) {
    AuthServiceConfig a;
    a.name = get_string(s, "name");
    a.url = get_string(s, "url");
    a.api_key = get_string(s, "api_key");
    auto mon = s["monitoring"];
    if (mon) {
      a.monitoring_path = get_string(mon, "path", false);
      a.monitoring_api_key = get_string(mon, "api_key", false);
    }
    cfg.auth_services.push_back(a);
  }

  auto log = root["log"];
  if (!log) throw std::runtime_error("missing log section");
  cfg.log.file = get_string(log, "file");
  cfg.log.level = get_string(log, "level");

  auto auth = root["auth"];
  if (auth) {
    cfg.connect_timeout_sec = get_int(auth, "connect_timeout_sec", false, cfg.connect_timeout_sec);
    cfg.response_timeout_sec = get_int(auth, "response_timeout_sec", false, cfg.response_timeout_sec);
  }

  auto mon = root["monitoring"];
  if (mon) {
    cfg.monitoring_enable = get_bool(mon, "enable", false, false);
    cfg.check_interval_sec = get_int(mon, "check_interval_sec", false, cfg.check_interval_sec);
  }

  return cfg;
}

} // namespace ovpnauth
