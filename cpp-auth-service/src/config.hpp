#pragma once

#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace authsvc {

struct LogConfig {
  std::string file;
  std::string level;
};

struct HttpTlsConfig {
  bool enable = false;
  std::string private_key;
  std::string certificate;
};

struct MonitoringConfig {
  bool enable = false;
  std::string path;
  std::string api_key;
};

struct WebServerConfig {
  std::string address;
  int port = 0;
  std::string auth_api_key;
  HttpTlsConfig https;
  MonitoringConfig status;
};

struct AuthCheckConfig {
  bool enable = false;
  int interval_sec = 0;
  std::string user;
  std::string pass;
};

struct RadiusServerConfig {
  std::string name;
  std::string address;
  int port = 1812;
  std::string protocol; // pap, mschapv2
  std::string secret;
  int response_timeout_sec = 5;
};

struct RadiusConfig {
  std::string nas_id;
  std::string nas_ipv4_address;
  int nas_port = 443;
  std::vector<RadiusServerConfig> servers;
};

struct LdapServerConfig {
  std::string name;
  std::string address;
  int port = 389;
  bool ssl = false;
  int response_timeout_sec = 5;
};

struct LdapConfig {
  std::string bind_dn;
  std::string pass;
  std::string search_base;
  std::string search_filter;
  bool verify_cert = false;
  std::vector<LdapServerConfig> servers;
};

struct AuthProviderConfig {
  std::string type; // radius or ldap
  AuthCheckConfig auth_check;
  RadiusConfig radius;
  LdapConfig ldap;
};

struct AppConfig {
  LogConfig log;
  WebServerConfig web_server;
  AuthProviderConfig auth_provider;
};

AppConfig load_config(const std::string& path);

} // namespace authsvc
