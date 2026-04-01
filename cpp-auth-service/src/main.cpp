#include "auth_clients.hpp"
#include "config.hpp"

#include <common/logging.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <csignal>
#include <memory>
#include <mutex>
#include <thread>

using json = nlohmann::json;

namespace authsvc {

struct AuthServiceState {
  AppConfig cfg;
  std::shared_ptr<spdlog::logger> logger;
  std::vector<int> available_servers;
  std::vector<int> unavailable_servers;
  std::mutex mtx;
};

static std::atomic<bool> g_stop{false};
static httplib::Server* g_http_server = nullptr;

static void signal_handler(int) {
  g_stop = true;
  if (g_http_server) {
    g_http_server->stop();
  }
}

static void run_auth_check(AuthServiceState* state,
                           RadiusAuthClient* radius_client,
                           LdapAuthClient* ldap_client) {
  const auto& cfg = state->cfg;
  auto interval = std::chrono::seconds(cfg.auth_provider.auth_check.interval_sec);

  while (!g_stop) {
    std::vector<int> available;
    std::vector<int> unavailable;

    int num = 0;
    if (cfg.auth_provider.type == "radius") {
      num = static_cast<int>(cfg.auth_provider.radius.servers.size());
    } else {
      num = static_cast<int>(cfg.auth_provider.ldap.servers.size());
    }

    for (int i = 0; i < num; ++i) {
      std::string err;
      bool ok = false;
      if (cfg.auth_provider.type == "radius") {
        ok = radius_client->check_authenticate(cfg.auth_provider.auth_check.user,
                                               cfg.auth_provider.auth_check.pass,
                                               i,
                                               &err);
      } else {
        ok = ldap_client->check_authenticate(cfg.auth_provider.auth_check.user,
                                             cfg.auth_provider.auth_check.pass,
                                             i,
                                             &err);
      }
      if (ok) {
        available.push_back(i);
      } else {
        unavailable.push_back(i);
        state->logger->error("Auth check failed for server {}: {}", i, err);
      }
    }

    {
      std::lock_guard<std::mutex> lock(state->mtx);
      state->available_servers = available;
      state->unavailable_servers = unavailable;
    }

    std::this_thread::sleep_for(interval);
  }
}

static int pick_available_server(AuthServiceState* state) {
  std::lock_guard<std::mutex> lock(state->mtx);
  if (!state->available_servers.empty()) {
    return state->available_servers.front();
  }
  return -1;
}

static json monitoring_status(AuthServiceState* state) {
  std::lock_guard<std::mutex> lock(state->mtx);
  if (state->available_servers.empty()) {
    return json{{"status_id", 3}, {"status_text", "err"}, {"msg", "None of authentication servers available"}};
  }
  if (!state->unavailable_servers.empty()) {
    std::string msg = std::to_string(state->available_servers.size()) + " of " +
                      std::to_string(state->available_servers.size() + state->unavailable_servers.size()) +
                      " authentication servers available";
    return json{{"status_id", 2}, {"status_text", "warn"}, {"msg", msg}};
  }
  return json{{"status_id", 1}, {"status_text", "ok"}};
}

} // namespace authsvc

int main(int argc, char** argv) {
  std::string config_path;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if ((arg == "--config" || arg == "-config") && i + 1 < argc) {
      config_path = argv[++i];
    }
  }

  if (config_path.empty()) {
    std::cerr << "Config file command line parameter must be present. Use --config <file>" << std::endl;
    return 1;
  }

  authsvc::AuthServiceState state;
  try {
    state.cfg = authsvc::load_config(config_path);
  } catch (const std::exception& e) {
    std::cerr << "Failed to load config: " << e.what() << std::endl;
    return 1;
  }

  state.logger = common::make_logger("auth-service", state.cfg.log.file, state.cfg.log.level);

  if (state.cfg.auth_provider.type != "radius" && state.cfg.auth_provider.type != "ldap") {
    state.logger->error("unsupported auth provider type");
    return 1;
  }

  int num_servers = 0;
  if (state.cfg.auth_provider.type == "radius") {
    num_servers = static_cast<int>(state.cfg.auth_provider.radius.servers.size());
  } else {
    num_servers = static_cast<int>(state.cfg.auth_provider.ldap.servers.size());
  }
  for (int i = 0; i < num_servers; ++i) state.available_servers.push_back(i);

  authsvc::RadiusAuthClient radius_client(state.cfg, state.logger);
  authsvc::LdapAuthClient ldap_client(state.cfg, state.logger);

  std::thread auth_check_thread;
  if (state.cfg.auth_provider.auth_check.enable) {
    auth_check_thread = std::thread(authsvc::run_auth_check, &state, &radius_client, &ldap_client);
  }

  std::unique_ptr<httplib::Server> server;
  if (state.cfg.web_server.https.enable) {
    server = std::make_unique<httplib::SSLServer>(state.cfg.web_server.https.certificate.c_str(),
                                                  state.cfg.web_server.https.private_key.c_str());
  } else {
    server = std::make_unique<httplib::Server>();
  }

  server->set_read_timeout(90, 0);
  server->set_write_timeout(90, 0);

  server->Post("/auth", [&](const httplib::Request& req, httplib::Response& res) {
    auto api_key = req.get_header_value("X-Api-Key");
    if (api_key != state.cfg.web_server.auth_api_key) {
      state.logger->error("X-Api-Key is invalid. Got: {}", api_key);
      res.status = 403;
      return;
    }
    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 403;
      return;
    }
    std::string user = body.value("u", "");
    std::string pass = body.value("p", "");
    std::string client_ip = body.value("client_ip", "");

    int server_idx = authsvc::pick_available_server(&state);
    if (server_idx < 0) {
      res.status = 403;
      return;
    }

    if (state.cfg.auth_provider.type == "radius") {
      authsvc::NetworkData nd;
      std::string err;
      bool ok = radius_client.authenticate(user, pass, client_ip, server_idx, &nd, &err);
      if (!ok) {
        res.status = 403;
        return;
      }
      res.set_header("X-Auth-Provider", "radius");
      json out{{"ip", nd.ip}, {"netmask", nd.netmask}};
      res.set_content(out.dump(), "application/json");
      res.status = 200;
      return;
    }

    if (state.cfg.auth_provider.type == "ldap") {
      std::string err;
      bool ok = ldap_client.authenticate(user, pass, server_idx, &err);
      if (!ok) {
        res.status = 403;
        return;
      }
      res.set_header("X-Auth-Provider", "ldap");
      res.status = 200;
      return;
    }

    res.status = 403;
  });

  if (state.cfg.web_server.status.enable) {
    server->Get(state.cfg.web_server.status.path.c_str(), [&](const httplib::Request& req, httplib::Response& res) {
      auto api_key = req.get_header_value("X-Api-Key");
      if (api_key != state.cfg.web_server.status.api_key) {
        res.status = 403;
        return;
      }
      json out = authsvc::monitoring_status(&state);
      res.set_content(out.dump(), "application/json");
      res.status = 200;
    });
  }

  authsvc::g_http_server = server.get();
  std::signal(SIGINT, authsvc::signal_handler);
  std::signal(SIGTERM, authsvc::signal_handler);

  state.logger->info("Auth service started on {}:{}", state.cfg.web_server.address, state.cfg.web_server.port);
  server->listen(state.cfg.web_server.address.c_str(), state.cfg.web_server.port);

  authsvc::g_stop = true;
  if (auth_check_thread.joinable()) {
    auth_check_thread.join();
  }

  state.logger->info("Auth service stopped");
  return 0;
}
