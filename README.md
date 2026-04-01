# OpenVPN multi-provider authentication plugin (C++ rewrite)

## DEV WARNING

This repository contains a DEV C++ rewrite. It is not production-ready yet.
Using it in production is NOT recommended at this time.

## Overview

The project provides a native OpenVPN authentication plugin and a companion authentication service.
Supported auth providers:

- RADIUS (PAP, MSCHAPv2)
- LDAP/LDAPS

Key features:

- non-blocking OpenVPN plugin API
- multi-provider authentication (RADIUS/LDAP)
- optional MFA via external providers integrated into LDAP/RADIUS
- multiple auth servers and health checks
- monitoring endpoint for auth-service

## Architecture

Two components:

1. OpenVPN plugin (`libopenvpn_auth_plugin.so`)
2. Auth service (`auth-service`)

They can run on the same server or on separate servers (HTTPS recommended in that case).

## Build (CMake)

Required system packages (Linux):

- `cmake`, `g++`, `make`
- `libssl-dev` (OpenSSL)
- `libldap2-dev` (OpenLDAP)
- `pkg-config`
- OpenVPN plugin headers (`openvpn-plugin.h`, usually from `openvpn-dev`)

Build steps:

```
mkdir -p build
cd build
cmake ..
cmake --build .
```

Outputs:

- `build/libopenvpn_auth_plugin.so`
- `build/auth-service`
- `build/radius-client`

## Configuration

The C++ code uses YAML config files compatible with the original layout.

### Auth service config

Use `auth-service/config.yml` as a template and place your final config, for example:

- `/etc/openvpn-multi-auth/auth-service.yml`

Run:

```
/usr/local/bin/auth-service --config /etc/openvpn-multi-auth/auth-service.yml
```

### OpenVPN plugin config

Use `openvpn-plugin/config.yml` as a template and place your final config, for example:

- `/etc/openvpn-multi-auth/openvpn-plugin.yml`

OpenVPN config snippet:

```
username-as-common-name
client-config-dir <path>
plugin <full-path-to-plugin>/libopenvpn_auth_plugin.so --config /etc/openvpn-multi-auth/openvpn-plugin.yml
```

## Testing authentication

Auth-service API call example:

```
curl -H "X-Api-Key: 123456789" -X POST --data '{"u": "user", "p": "user_password", "client_ip": "127.0.0.1"}' -i http://127.0.0.1:11245/auth
```

Where `X-Api-Key` must match `web_server.auth_api_key` in the auth-service config.

## Monitoring

If enabled in the auth-service config, a status endpoint is available.
Example:

```
curl -v -H "X-Api-Key: 987654321" http://127.0.0.1:11245/status/121233456
```

Response format:

```json
{
  "status_id": 1,
  "status_text": "ok",
  "msg": ""
}
```

## systemd unit (auth-service)

A sample unit is included at `systemd/openvpn-multi-auth.service`.

Default paths in the unit:

- Binary: `/usr/local/bin/auth-service`
- Config: `/etc/openvpn-multi-auth/auth-service.yml`
- User/Group: `openvpn`

Adjust these paths as needed for your deployment.
