#include "config.hpp"

#include <stdexcept>

namespace authsvc {

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

AppConfig load_config(const std::string& path) {
  auto root = YAML::LoadFile(path);
  AppConfig cfg;

  auto log = root["log"];
  if (!log) throw std::runtime_error("missing log section");
  cfg.log.file = get_string(log, "file");
  cfg.log.level = get_string(log, "level");

  auto ws = root["web_server"];
  if (!ws) throw std::runtime_error("missing web_server section");
  cfg.web_server.address = get_string(ws, "listen_address");
  cfg.web_server.port = get_int(ws, "port");
  cfg.web_server.auth_api_key = get_string(ws, "auth_api_key");

  auto https = ws["https"];
  if (https) {
    cfg.web_server.https.enable = get_bool(https, "enable", false, false);
    cfg.web_server.https.private_key = get_string(https, "private_key", false);
    cfg.web_server.https.certificate = get_string(https, "certificate", false);
  }

  auto status = ws["status"];
  if (status) {
    cfg.web_server.status.enable = get_bool(status, "enable", false, false);
    cfg.web_server.status.path = get_string(status, "path", false);
    cfg.web_server.status.api_key = get_string(status, "api_key", false);
  }

  auto ap = root["auth_provider"];
  if (!ap) throw std::runtime_error("missing auth_provider section");
  cfg.auth_provider.type = get_string(ap, "type");

  auto auth_check = ap["auth_check"];
  if (auth_check) {
    cfg.auth_provider.auth_check.enable = get_bool(auth_check, "enable", false, false);
    cfg.auth_provider.auth_check.interval_sec = get_int(auth_check, "interval_sec", false, 0);
    cfg.auth_provider.auth_check.user = get_string(auth_check, "user", false);
    cfg.auth_provider.auth_check.pass = get_string(auth_check, "pass", false);
  }

  auto radius = ap["radius"];
  if (radius) {
    cfg.auth_provider.radius.nas_id = get_string(radius, "nas_id", false);
    cfg.auth_provider.radius.nas_ipv4_address = get_string(radius, "nas_ipv4_address", false);
    cfg.auth_provider.radius.nas_port = get_int(radius, "nas_port", false, 443);
    auto servers = radius["servers"];
    if (servers) {
      for (const auto& s : servers) {
        RadiusServerConfig sc;
        sc.name = get_string(s, "name");
        sc.address = get_string(s, "address");
        sc.port = get_int(s, "port");
        sc.protocol = get_string(s, "protocol");
        sc.secret = get_string(s, "secret");
        sc.response_timeout_sec = get_int(s, "response_timeout_sec", false, 5);
        cfg.auth_provider.radius.servers.push_back(sc);
      }
    }
  }

  auto ldap = ap["ldap"];
  if (ldap) {
    cfg.auth_provider.ldap.bind_dn = get_string(ldap, "bind_dn", false);
    cfg.auth_provider.ldap.pass = get_string(ldap, "pass", false);
    cfg.auth_provider.ldap.search_base = get_string(ldap, "search_base", false);
    cfg.auth_provider.ldap.search_filter = get_string(ldap, "search_filter", false);
    cfg.auth_provider.ldap.verify_cert = get_bool(ldap, "verify_cert", false, false);
    auto servers = ldap["servers"];
    if (servers) {
      for (const auto& s : servers) {
        LdapServerConfig sc;
        sc.name = get_string(s, "name");
        sc.address = get_string(s, "address");
        sc.port = get_int(s, "port");
        sc.ssl = get_bool(s, "ssl", false, false);
        sc.response_timeout_sec = get_int(s, "response_timeout_sec", false, 5);
        cfg.auth_provider.ldap.servers.push_back(sc);
      }
    }
  }

  return cfg;
}

} // namespace authsvc
