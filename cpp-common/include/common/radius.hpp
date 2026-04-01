#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#error "RADIUS client implementation targets Linux/Unix sockets"
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace common {
namespace radius {

enum class Code : uint8_t {
  AccessRequest = 1,
  AccessAccept = 2,
  AccessReject = 3,
  AccessChallenge = 11,
};

struct Server {
  std::string address;
  int port = 1812;
  std::string secret;
  std::string proto; // "pap" or "mschapv2"
  int timeout_sec = 5;
  std::string name;
};

struct NetworkData {
  std::string ip;
  std::string netmask;
};

struct AuthRequest {
  std::string user;
  std::string pass;
  std::string client_ip;
  std::string nas_id;
  std::string nas_ipv4;
  uint32_t nas_port = 443;
};

struct Attribute {
  uint8_t type = 0;
  std::vector<uint8_t> data;
};

inline std::vector<uint8_t> random_bytes(size_t n) {
  std::vector<uint8_t> out(n);
  std::random_device rd;
  for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(rd());
  return out;
}

inline std::vector<uint8_t> md5(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(MD5_DIGEST_LENGTH);
  MD5(data.data(), data.size(), out.data());
  return out;
}

inline std::vector<uint8_t> md4(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(MD4_DIGEST_LENGTH);
  MD4(data.data(), data.size(), out.data());
  return out;
}

inline std::vector<uint8_t> sha1(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(SHA_DIGEST_LENGTH);
  SHA1(data.data(), data.size(), out.data());
  return out;
}

inline std::vector<uint8_t> to_utf16le(const std::string& s) {
  std::vector<uint8_t> out;
  out.reserve(s.size() * 2);
  for (unsigned char c : s) {
    out.push_back(c);
    out.push_back(0x00);
  }
  return out;
}

inline void make_des_key(const uint8_t in[7], DES_cblock* out) {
  (*out)[0] = in[0];
  (*out)[1] = static_cast<uint8_t>((in[0] << 7) | (in[1] >> 1));
  (*out)[2] = static_cast<uint8_t>((in[1] << 6) | (in[2] >> 2));
  (*out)[3] = static_cast<uint8_t>((in[2] << 5) | (in[3] >> 3));
  (*out)[4] = static_cast<uint8_t>((in[3] << 4) | (in[4] >> 4));
  (*out)[5] = static_cast<uint8_t>((in[4] << 3) | (in[5] >> 5));
  (*out)[6] = static_cast<uint8_t>((in[5] << 2) | (in[6] >> 6));
  (*out)[7] = static_cast<uint8_t>(in[6] << 1);
  DES_set_odd_parity(out);
}

inline std::vector<uint8_t> des_encrypt(const uint8_t key7[7], const uint8_t data8[8]) {
  DES_cblock key;
  make_des_key(key7, &key);
  DES_key_schedule ks;
  DES_set_key_unchecked(&key, &ks);
  DES_cblock input;
  std::memcpy(input, data8, 8);
  DES_cblock output;
  DES_ecb_encrypt(&input, &output, &ks, DES_ENCRYPT);
  return std::vector<uint8_t>(output, output + 8);
}

inline std::vector<uint8_t> challenge_response(const std::vector<uint8_t>& challenge8,
                                               const std::vector<uint8_t>& nt_hash16) {
  std::vector<uint8_t> zhash(21, 0x00);
  std::memcpy(zhash.data(), nt_hash16.data(), nt_hash16.size());
  std::vector<uint8_t> resp;
  resp.reserve(24);

  auto r1 = des_encrypt(&zhash[0], challenge8.data());
  auto r2 = des_encrypt(&zhash[7], challenge8.data());
  auto r3 = des_encrypt(&zhash[14], challenge8.data());
  resp.insert(resp.end(), r1.begin(), r1.end());
  resp.insert(resp.end(), r2.begin(), r2.end());
  resp.insert(resp.end(), r3.begin(), r3.end());
  return resp;
}

inline std::vector<uint8_t> ms_chap_v2_nt_response(const std::vector<uint8_t>& authenticator_challenge,
                                                   const std::vector<uint8_t>& peer_challenge,
                                                   const std::string& username,
                                                   const std::string& password) {
  std::vector<uint8_t> challenge_hash_in;
  challenge_hash_in.reserve(peer_challenge.size() + authenticator_challenge.size() + username.size());
  challenge_hash_in.insert(challenge_hash_in.end(), peer_challenge.begin(), peer_challenge.end());
  challenge_hash_in.insert(challenge_hash_in.end(), authenticator_challenge.begin(), authenticator_challenge.end());
  challenge_hash_in.insert(challenge_hash_in.end(), username.begin(), username.end());

  auto sha = sha1(challenge_hash_in);
  std::vector<uint8_t> challenge(8);
  std::memcpy(challenge.data(), sha.data(), 8);

  auto pass_utf16 = to_utf16le(password);
  auto nt_hash = md4(pass_utf16);
  return challenge_response(challenge, nt_hash);
}

inline std::vector<uint8_t> encrypt_user_password(const std::string& password,
                                                  const std::string& secret,
                                                  const std::array<uint8_t, 16>& authenticator) {
  std::vector<uint8_t> pwd(password.begin(), password.end());
  size_t padded = ((pwd.size() + 15) / 16) * 16;
  pwd.resize(padded, 0x00);

  std::vector<uint8_t> out;
  out.reserve(pwd.size());

  std::vector<uint8_t> b_input(secret.begin(), secret.end());
  b_input.insert(b_input.end(), authenticator.begin(), authenticator.end());
  auto b = md5(b_input);

  for (size_t i = 0; i < pwd.size(); i += 16) {
    std::vector<uint8_t> c(16);
    for (size_t j = 0; j < 16; ++j) {
      c[j] = pwd[i + j] ^ b[j];
    }
    out.insert(out.end(), c.begin(), c.end());

    std::vector<uint8_t> next_input(secret.begin(), secret.end());
    next_input.insert(next_input.end(), c.begin(), c.end());
    b = md5(next_input);
  }
  return out;
}

inline void add_attr(std::vector<uint8_t>& out, uint8_t type, const std::vector<uint8_t>& data) {
  uint8_t len = static_cast<uint8_t>(data.size() + 2);
  out.push_back(type);
  out.push_back(len);
  out.insert(out.end(), data.begin(), data.end());
}

inline void add_string_attr(std::vector<uint8_t>& out, uint8_t type, const std::string& val) {
  add_attr(out, type, std::vector<uint8_t>(val.begin(), val.end()));
}

inline void add_int_attr(std::vector<uint8_t>& out, uint8_t type, uint32_t value) {
  uint32_t v = htonl(value);
  std::vector<uint8_t> data(4);
  std::memcpy(data.data(), &v, 4);
  add_attr(out, type, data);
}

inline void add_ipv4_attr(std::vector<uint8_t>& out, uint8_t type, const std::string& ip) {
  in_addr addr{};
  if (inet_aton(ip.c_str(), &addr) == 0) return;
  std::vector<uint8_t> data(4);
  std::memcpy(data.data(), &addr.s_addr, 4);
  add_attr(out, type, data);
}

inline void add_vendor_specific(std::vector<uint8_t>& out,
                                uint32_t vendor_id,
                                uint8_t vendor_type,
                                const std::vector<uint8_t>& vendor_data) {
  std::vector<uint8_t> data;
  data.resize(4 + 2 + vendor_data.size());
  uint32_t vid = htonl(vendor_id);
  std::memcpy(data.data(), &vid, 4);
  data[4] = vendor_type;
  data[5] = static_cast<uint8_t>(vendor_data.size() + 2);
  std::memcpy(data.data() + 6, vendor_data.data(), vendor_data.size());
  add_attr(out, 26, data);
}

inline bool send_packet(const std::string& host,
                        int port,
                        const std::vector<uint8_t>& packet,
                        int timeout_sec,
                        std::vector<uint8_t>& response,
                        std::string* err) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* res = nullptr;
  std::string port_str = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
    if (err) *err = "getaddrinfo failed";
    return false;
  }

  int sock = -1;
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock == -1) continue;
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(sock, packet.data(), packet.size(), 0, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock);
      sock = -1;
      continue;
    }

    response.resize(4096);
    ssize_t n = recvfrom(sock, response.data(), response.size(), 0, nullptr, nullptr);
    if (n > 0) {
      response.resize(static_cast<size_t>(n));
      close(sock);
      freeaddrinfo(res);
      return true;
    }
    close(sock);
    sock = -1;
  }

  freeaddrinfo(res);
  if (err) *err = "no response";
  return false;
}

inline bool authenticate(const AuthRequest& req,
                         const Server& srv,
                         NetworkData* out,
                         std::shared_ptr<spdlog::logger> logger,
                         std::string* err) {
  uint8_t identifier = random_bytes(1)[0];
  std::array<uint8_t, 16> authenticator{};
  auto auth = random_bytes(16);
  std::memcpy(authenticator.data(), auth.data(), 16);

  std::vector<uint8_t> attrs;
  add_string_attr(attrs, 1, req.user); // User-Name
  if (!req.nas_id.empty()) add_string_attr(attrs, 32, req.nas_id); // NAS-Identifier
  if (!req.nas_ipv4.empty()) add_ipv4_attr(attrs, 4, req.nas_ipv4); // NAS-IP-Address
  add_int_attr(attrs, 5, req.nas_port); // NAS-Port
  add_int_attr(attrs, 61, 5); // NAS-Port-Type = Virtual
  if (!req.client_ip.empty()) add_string_attr(attrs, 31, req.client_ip); // Calling-Station-Id

  if (srv.proto == "pap") {
    auto enc = encrypt_user_password(req.pass, srv.secret, authenticator);
    add_attr(attrs, 2, enc); // User-Password
  } else if (srv.proto == "mschapv2") {
    auto authenticator_challenge = random_bytes(16);
    auto peer_challenge = random_bytes(16);
    auto nt_resp = ms_chap_v2_nt_response(authenticator_challenge, peer_challenge, req.user, req.pass);

    add_vendor_specific(attrs, 311, 11, authenticator_challenge); // MS-CHAP-Challenge

    std::vector<uint8_t> resp;
    resp.reserve(50);
    resp.push_back('1');
    resp.push_back('0');
    resp.insert(resp.end(), peer_challenge.begin(), peer_challenge.end());
    resp.insert(resp.end(), 8, 0x00);
    resp.insert(resp.end(), nt_resp.begin(), nt_resp.end());
    add_vendor_specific(attrs, 311, 25, resp); // MS-CHAP2-Response
  } else {
    if (err) *err = "unsupported proto";
    return false;
  }

  uint16_t length = static_cast<uint16_t>(20 + attrs.size());
  std::vector<uint8_t> packet;
  packet.reserve(length);
  packet.push_back(static_cast<uint8_t>(Code::AccessRequest));
  packet.push_back(identifier);
  packet.push_back(static_cast<uint8_t>((length >> 8) & 0xff));
  packet.push_back(static_cast<uint8_t>(length & 0xff));
  packet.insert(packet.end(), authenticator.begin(), authenticator.end());
  packet.insert(packet.end(), attrs.begin(), attrs.end());

  std::vector<uint8_t> response;
  if (!send_packet(srv.address, srv.port, packet, srv.timeout_sec, response, err)) {
    if (logger) logger->error("RADIUS send failed: {}", err ? *err : "");
    return false;
  }
  if (response.size() < 20) {
    if (err) *err = "short response";
    return false;
  }

  Code resp_code = static_cast<Code>(response[0]);
  uint8_t resp_id = response[1];
  uint16_t resp_len = static_cast<uint16_t>((response[2] << 8) | response[3]);
  if (resp_id != identifier || resp_len != response.size()) {
    if (err) *err = "invalid response";
    return false;
  }

  // verify response authenticator
  std::vector<uint8_t> auth_input;
  auth_input.reserve(4 + 16 + (response.size() - 20) + srv.secret.size());
  auth_input.insert(auth_input.end(), response.begin(), response.begin() + 4);
  auth_input.insert(auth_input.end(), authenticator.begin(), authenticator.end());
  auth_input.insert(auth_input.end(), response.begin() + 20, response.end());
  auth_input.insert(auth_input.end(), srv.secret.begin(), srv.secret.end());
  auto calc = md5(auth_input);
  if (std::memcmp(calc.data(), response.data() + 4, 16) != 0) {
    if (err) *err = "bad response authenticator";
    return false;
  }

  if (resp_code != Code::AccessAccept) {
    if (err) *err = "access rejected";
    return false;
  }

  if (out) {
    size_t pos = 20;
    while (pos + 2 <= response.size()) {
      uint8_t type = response[pos];
      uint8_t len = response[pos + 1];
      if (len < 2 || pos + len > response.size()) break;
      const uint8_t* data = response.data() + pos + 2;
      size_t data_len = len - 2;
      if (type == 8 && data_len == 4) { // Framed-IP-Address
        char buf[INET_ADDRSTRLEN];
        in_addr addr{};
        std::memcpy(&addr.s_addr, data, 4);
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        out->ip = buf;
      } else if (type == 9 && data_len == 4) { // Framed-IP-Netmask
        char buf[INET_ADDRSTRLEN];
        in_addr addr{};
        std::memcpy(&addr.s_addr, data, 4);
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        out->netmask = buf;
      }
      pos += len;
    }
  }

  return true;
}

} // namespace radius
} // namespace common
