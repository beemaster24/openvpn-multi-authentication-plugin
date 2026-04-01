#include "config.hpp"

#include <common/logging.hpp>
#include <common/url.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include <openvpn-plugin.h>
}

using json = nlohmann::json;

namespace ovpnauth {

struct PluginContext {
  PluginConfig cfg;
  std::shared_ptr<spdlog::logger> logger;
  std::string ccd_dir;
  std::vector<size_t> available_services;
  std::mutex mtx;
  std::atomic<bool> stop{false};
  std::thread monitoring_thread;
};

static std::string get_env_value(const char** envp, const std::string& key) {
  if (!envp) return "";
  std::string prefix = key + "=";
  for (int i = 0; envp[i] != nullptr; ++i) {
    const char* e = envp[i];
    if (std::strncmp(e, prefix.c_str(), prefix.size()) == 0) {
      return std::string(e + prefix.size());
    }
  }
  return "";
}

static std::string find_ccd(const std::string& config_path, std::shared_ptr<spdlog::logger> logger) {
  std::ifstream f(config_path);
  if (!f) return "";
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("client-config-dir", 0) == 0) {
      auto pos = line.find(' ');
      if (pos != std::string::npos) {
        return line.substr(pos + 1);
      }
    }
  }
  return "";
}

static bool write_auth_control(const std::string& path, const std::string& value, std::shared_ptr<spdlog::logger> logger) {
  std::ofstream f(path, std::ios::trunc);
  if (!f) {
    if (logger) logger->error("Unable to write auth_control_file {}", path);
    return false;
  }
  f << value;
  return true;
}

static void write_ccd(std::shared_ptr<spdlog::logger> logger,
                      const std::string& ccd_dir,
                      const std::string& username,
                      const std::string& ip,
                      const std::string& netmask) {
  if (ccd_dir.empty()) return;
  if (ip.empty() || netmask.empty()) return;
  std::string path = ccd_dir;
  if (path.back() != '/') path += "/";
  path += username;

  std::ofstream f(path, std::ios::trunc);
  if (!f) {
    if (logger) logger->error("Can't write CCD file {}", path);
    return;
  }
  f << "topology subnet\n";
  f << "ifconfig-push " << ip << " " << netmask << "\n";
}

static bool http_auth_request(PluginContext* ctx,
                              const AuthServiceConfig& svc,
                              const std::string& user,
                              const std::string& pass,
                              const std::string& client_ip,
                              std::string* out_provider,
                              std::string* out_ip,
                              std::string* out_netmask) {
  common::UrlParts url;
  std::string err;
  if (!common::parse_url(svc.url, url, &err)) {
    ctx->logger->error("Bad auth service url {}: {}", svc.url, err);
    return false;
  }

  std::unique_ptr<httplib::Client> cli;
  if (url.https) {
    auto ssl = std::make_unique<httplib::SSLClient>(url.host.c_str(), url.port);
    ssl->enable_server_certificate_verification(ctx->cfg.verify_cert);
    cli = std::move(ssl);
  } else {
    cli = std::make_unique<httplib::Client>(url.host.c_str(), url.port);
  }

  cli->set_connection_timeout(ctx->cfg.connect_timeout_sec, 0);
  cli->set_read_timeout(ctx->cfg.response_timeout_sec, 0);

  json body{{"u", user}, {"p", pass}, {"client_ip", client_ip}};
  httplib::Headers headers{{"X-Api-Key", svc.api_key}};

  auto path = url.path;
  if (path.back() == '/') path.pop_back();
  path += "/auth";

  auto res = cli->Post(path.c_str(), headers, body.dump(), "application/json");
  if (!res) {
    ctx->logger->error("Auth request failed to {}", svc.url);
    return false;
  }
  if (res->status != 200) {
    return false;
  }
  auto provider = res->get_header_value("X-Auth-Provider");
  if (provider.empty()) {
    ctx->logger->error("Missing X-Auth-Provider header");
    return false;
  }
  if (out_provider) *out_provider = provider;

  if (provider == "radius") {
    try {
      auto j = json::parse(res->body);
      if (out_ip) *out_ip = j.value("ip", "");
      if (out_netmask) *out_netmask = j.value("netmask", "");
    } catch (...) {
      ctx->logger->error("Failed to parse radius response body");
      return false;
    }
  }

  return true;
}

static void auth_task(PluginContext* ctx,
                      const std::string& user,
                      const std::string& pass,
                      const std::string& client_ip,
                      const std::string& auth_control_file) {
  size_t idx = 0;
  {
    std::lock_guard<std::mutex> lock(ctx->mtx);
    if (ctx->available_services.empty()) {
      ctx->logger->error("No available auth services");
      write_auth_control(auth_control_file, "0", ctx->logger);
      return;
    }
    idx = ctx->available_services.front();
  }

  const auto& svc = ctx->cfg.auth_services[idx];
  std::string provider;
  std::string ip;
  std::string netmask;
  bool ok = http_auth_request(ctx, svc, user, pass, client_ip, &provider, &ip, &netmask);
  if (!ok) {
    write_auth_control(auth_control_file, "0", ctx->logger);
    return;
  }

  if (provider == "radius") {
    write_ccd(ctx->logger, ctx->ccd_dir, user, ip, netmask);
  }
  write_auth_control(auth_control_file, "1", ctx->logger);
}

static void monitoring_loop(PluginContext* ctx) {
  while (!ctx->stop) {
    std::vector<size_t> available;
    for (size_t i = 0; i < ctx->cfg.auth_services.size(); ++i) {
      const auto& svc = ctx->cfg.auth_services[i];
      if (svc.monitoring_path.empty() || svc.monitoring_api_key.empty()) continue;

      common::UrlParts url;
      std::string err;
      if (!common::parse_url(svc.url, url, &err)) {
        ctx->logger->error("Bad auth service url {}: {}", svc.url, err);
        continue;
      }

      std::unique_ptr<httplib::Client> cli;
      if (url.https) {
        auto ssl = std::make_unique<httplib::SSLClient>(url.host.c_str(), url.port);
        ssl->enable_server_certificate_verification(ctx->cfg.verify_cert);
        cli = std::move(ssl);
      } else {
        cli = std::make_unique<httplib::Client>(url.host.c_str(), url.port);
      }
      cli->set_connection_timeout(ctx->cfg.connect_timeout_sec, 0);
      cli->set_read_timeout(ctx->cfg.response_timeout_sec, 0);

      auto path = url.path;
      if (path.back() == '/') path.pop_back();
      path += svc.monitoring_path;

      httplib::Headers headers{{"X-Api-Key", svc.monitoring_api_key}};
      auto res = cli->Get(path.c_str(), headers);
      if (!res || res->status != 200) {
        continue;
      }
      try {
        auto j = json::parse(res->body);
        int status_id = j.value("status_id", 3);
        if (status_id != 3) {
          available.push_back(i);
        }
      } catch (...) {
        continue;
      }
    }

    {
      std::lock_guard<std::mutex> lock(ctx->mtx);
      if (!available.empty()) ctx->available_services = available;
    }

    std::this_thread::sleep_for(std::chrono::seconds(ctx->cfg.check_interval_sec));
  }
}

} // namespace ovpnauth

extern "C" OPENVPN_EXPORT int openvpn_plugin_open_v3(const struct openvpn_plugin_args_open_in* args,
                                                     struct openvpn_plugin_args_open_return* ret) {
  if (!args || !ret) return OPENVPN_PLUGIN_FUNC_ERROR;

  std::string config_path;
  for (int i = 0; i < args->argc; ++i) {
    if (std::strcmp(args->argv[i], "--config") == 0 && i + 1 < args->argc) {
      config_path = args->argv[i + 1];
      break;
    }
  }
  if (config_path.empty()) return OPENVPN_PLUGIN_FUNC_ERROR;

  auto ctx = new ovpnauth::PluginContext();
  try {
    ctx->cfg = ovpnauth::load_config(config_path);
  } catch (...) {
    delete ctx;
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  ctx->logger = common::make_logger("auth-plugin", ctx->cfg.log.file, ctx->cfg.log.level);

  std::string ovpn_config = ovpnauth::get_env_value(args->envp, "config");
  if (!ovpn_config.empty()) {
    ctx->ccd_dir = ovpnauth::find_ccd(ovpn_config, ctx->logger);
  }

  for (size_t i = 0; i < ctx->cfg.auth_services.size(); ++i) {
    ctx->available_services.push_back(i);
  }

  if (ctx->cfg.monitoring_enable) {
    ctx->monitoring_thread = std::thread(ovpnauth::monitoring_loop, ctx);
  }

  ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) |
                   OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2) |
                   OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
  ret->handle = reinterpret_cast<openvpn_plugin_handle_t>(ctx);

  return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

extern "C" OPENVPN_EXPORT int openvpn_plugin_func_v3(const struct openvpn_plugin_args_func_in* args,
                                                     struct openvpn_plugin_args_func_return* ret) {
  if (!args || !ret) return OPENVPN_PLUGIN_FUNC_ERROR;
  auto* ctx = reinterpret_cast<ovpnauth::PluginContext*>(args->handle);
  if (!ctx) return OPENVPN_PLUGIN_FUNC_ERROR;

  if (args->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
    std::string user = ovpnauth::get_env_value(args->envp, "username");
    std::string pass = ovpnauth::get_env_value(args->envp, "password");
    std::string client_ip = ovpnauth::get_env_value(args->envp, "untrusted_ip");
    std::string auth_control_file = ovpnauth::get_env_value(args->envp, "auth_control_file");
    if (user.empty() || pass.empty() || auth_control_file.empty()) {
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    std::thread t(ovpnauth::auth_task, ctx, user, pass, client_ip, auth_control_file);
    t.detach();
    return OPENVPN_PLUGIN_FUNC_DEFERRED;
  }

  return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

extern "C" OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
  auto* ctx = reinterpret_cast<ovpnauth::PluginContext*>(handle);
  if (!ctx) return;
  ctx->stop = true;
  if (ctx->monitoring_thread.joinable()) {
    ctx->monitoring_thread.join();
  }
  delete ctx;
}
