#include <common/radius.hpp>

#include <iostream>
#include <string>

struct CmdOpts {
  std::string address;
  std::string user;
  std::string password;
  std::string proto;
  std::string secret;
  std::string nas_id;
  uint32_t nas_port = 443;
};

static void usage() {
  std::cout << "Usage: radius-client --addr host:port -u user -p pass --proto pap|mschapv2 -s secret [--nid nasid] [--np nasport]\n";
}

static bool parse_args(int argc, char** argv, CmdOpts& out) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--addr" && i + 1 < argc) out.address = argv[++i];
    else if (arg == "-u" && i + 1 < argc) out.user = argv[++i];
    else if (arg == "-p" && i + 1 < argc) out.password = argv[++i];
    else if (arg == "--proto" && i + 1 < argc) out.proto = argv[++i];
    else if (arg == "-s" && i + 1 < argc) out.secret = argv[++i];
    else if (arg == "--nid" && i + 1 < argc) out.nas_id = argv[++i];
    else if (arg == "--np" && i + 1 < argc) out.nas_port = static_cast<uint32_t>(std::stoul(argv[++i]));
    else {
      usage();
      return false;
    }
  }
  if (out.address.empty() || out.user.empty() || out.password.empty() || out.proto.empty() || out.secret.empty()) {
    usage();
    return false;
  }
  return true;
}

int main(int argc, char** argv) {
  CmdOpts opts;
  if (!parse_args(argc, argv, opts)) return 1;

  auto pos = opts.address.find(':');
  if (pos == std::string::npos) {
    std::cerr << "--addr must be host:port" << std::endl;
    return 1;
  }

  common::radius::Server srv;
  srv.address = opts.address.substr(0, pos);
  srv.port = std::stoi(opts.address.substr(pos + 1));
  srv.secret = opts.secret;
  srv.proto = opts.proto;
  srv.timeout_sec = 30;

  common::radius::AuthRequest req;
  req.user = opts.user;
  req.pass = opts.password;
  req.nas_id = opts.nas_id;
  req.nas_port = opts.nas_port;

  common::radius::NetworkData nd;
  std::string err;
  bool ok = common::radius::authenticate(req, srv, &nd, nullptr, &err);
  if (!ok) {
    std::cerr << "Authentication failed: " << err << std::endl;
    return 1;
  }

  std::cout << "Authentication success" << std::endl;
  std::cout << "Framed-IP-Address: " << nd.ip << std::endl;
  std::cout << "Framed-IP-Netmask: " << nd.netmask << std::endl;
  return 0;
}
