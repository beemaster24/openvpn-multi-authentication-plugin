#pragma once

#include "config.hpp"
#include <common/radius.hpp>
#include <spdlog/spdlog.h>

#include <ldap.h>

#include <string>

namespace authsvc {

struct NetworkData {
  std::string ip;
  std::string netmask;
};

class RadiusAuthClient {
 public:
  RadiusAuthClient(const AppConfig& cfg, std::shared_ptr<spdlog::logger> logger)
      : cfg_(cfg), logger_(std::move(logger)) {}

  bool authenticate(const std::string& user,
                    const std::string& pass,
                    const std::string& client_ip,
                    int server_idx,
                    NetworkData* out,
                    std::string* err) {
    if (server_idx < 0 || server_idx >= static_cast<int>(cfg_.auth_provider.radius.servers.size())) {
      if (err) *err = "server index out of range";
      return false;
    }
    const auto& s = cfg_.auth_provider.radius.servers[server_idx];
    common::radius::Server srv;
    srv.address = s.address;
    srv.port = s.port;
    srv.secret = s.secret;
    srv.proto = s.protocol;
    srv.timeout_sec = s.response_timeout_sec;
    srv.name = s.name;

    common::radius::AuthRequest req;
    req.user = user;
    req.pass = pass;
    req.client_ip = client_ip;
    req.nas_id = cfg_.auth_provider.radius.nas_id;
    req.nas_ipv4 = cfg_.auth_provider.radius.nas_ipv4_address;
    req.nas_port = static_cast<uint32_t>(cfg_.auth_provider.radius.nas_port);

    common::radius::NetworkData nd;
    bool ok = common::radius::authenticate(req, srv, &nd, logger_, err);
    if (ok && out) {
      out->ip = nd.ip;
      out->netmask = nd.netmask;
    }
    return ok;
  }

  bool check_authenticate(const std::string& user, const std::string& pass, int server_idx, std::string* err) {
    return authenticate(user, pass, "", server_idx, nullptr, err);
  }

 private:
  const AppConfig& cfg_;
  std::shared_ptr<spdlog::logger> logger_;
};

class LdapAuthClient {
 public:
  LdapAuthClient(const AppConfig& cfg, std::shared_ptr<spdlog::logger> logger)
      : cfg_(cfg), logger_(std::move(logger)) {}

  bool authenticate(const std::string& user,
                    const std::string& pass,
                    int server_idx,
                    std::string* err) {
    if (server_idx < 0 || server_idx >= static_cast<int>(cfg_.auth_provider.ldap.servers.size())) {
      if (err) *err = "server index out of range";
      return false;
    }
    const auto& s = cfg_.auth_provider.ldap.servers[server_idx];

    std::string url = (s.ssl ? "ldaps://" : "ldap://") + s.address + ":" + std::to_string(s.port);

    LDAP* ld = nullptr;
    int rc = ldap_initialize(&ld, url.c_str());
    if (rc != LDAP_SUCCESS || !ld) {
      if (err) *err = "ldap_initialize failed";
      return false;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (s.ssl) {
      int verify = cfg_.auth_provider.ldap.verify_cert ? LDAP_OPT_X_TLS_HARD : LDAP_OPT_X_TLS_ALLOW;
      ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &verify);
    }

    rc = ldap_simple_bind_s(ld, cfg_.auth_provider.ldap.bind_dn.c_str(), cfg_.auth_provider.ldap.pass.c_str());
    if (rc != LDAP_SUCCESS) {
      if (err) *err = "ldap bind (service account) failed";
      ldap_unbind_ext_s(ld, nullptr, nullptr);
      return false;
    }

    std::string filter = cfg_.auth_provider.ldap.search_filter;
    size_t pos = filter.find("%s");
    if (pos != std::string::npos) {
      filter.replace(pos, 2, user);
    }

    LDAPMessage* result = nullptr;
    rc = ldap_search_ext_s(ld,
                           cfg_.auth_provider.ldap.search_base.c_str(),
                           LDAP_SCOPE_SUBTREE,
                           filter.c_str(),
                           nullptr,
                           0,
                           nullptr,
                           nullptr,
                           nullptr,
                           0,
                           &result);
    if (rc != LDAP_SUCCESS) {
      if (err) *err = "ldap search failed";
      if (result) ldap_msgfree(result);
      ldap_unbind_ext_s(ld, nullptr, nullptr);
      return false;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
      if (err) *err = "user not found";
      ldap_msgfree(result);
      ldap_unbind_ext_s(ld, nullptr, nullptr);
      return false;
    }

    char* dn = ldap_get_dn(ld, entry);
    if (!dn) {
      if (err) *err = "ldap_get_dn failed";
      ldap_msgfree(result);
      ldap_unbind_ext_s(ld, nullptr, nullptr);
      return false;
    }

    rc = ldap_simple_bind_s(ld, dn, pass.c_str());
    ldap_memfree(dn);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    if (rc != LDAP_SUCCESS) {
      if (err) *err = "ldap user bind failed";
      return false;
    }
    return true;
  }

  bool check_authenticate(const std::string& user, const std::string& pass, int server_idx, std::string* err) {
    return authenticate(user, pass, server_idx, err);
  }

 private:
  const AppConfig& cfg_;
  std::shared_ptr<spdlog::logger> logger_;
};

} // namespace authsvc
