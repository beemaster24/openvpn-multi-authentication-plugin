cmake_minimum_required(VERSION 3.15)
project(openvpn_multi_auth_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Dependencies: cpp-httplib
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.16.2
)
FetchContent_MakeAvailable(httplib)

# nlohmann/json
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# spdlog
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
)
FetchContent_MakeAvailable(spdlog)

# yaml-cpp
FetchContent_Declare(
  yaml_cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG yaml-cpp-0.8.0
)
FetchContent_MakeAvailable(yaml_cpp)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDAP REQUIRED ldap)

if (TARGET httplib::httplib)
  set(HTTPLIB_TARGET httplib::httplib)
else()
  set(HTTPLIB_TARGET httplib)
endif()

# OpenVPN plugin headers
find_path(OPENVPN_PLUGIN_INCLUDE_DIR openvpn-plugin.h)

add_library(common_headers INTERFACE)
target_include_directories(common_headers INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/cpp-common/include
)

# Auth service
add_executable(auth-service
  cpp-auth-service/src/main.cpp
  cpp-auth-service/src/config.cpp
)

target_include_directories(auth-service PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/cpp-auth-service/src
  ${LDAP_INCLUDE_DIRS}
)

target_link_libraries(auth-service
  PRIVATE
    common_headers
    spdlog::spdlog
    yaml-cpp
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${LDAP_LIBRARIES}
    ${HTTPLIB_TARGET}
    nlohmann_json::nlohmann_json
)

target_compile_definitions(auth-service PRIVATE HTTPLIB_OPENSSL_SUPPORT)

# OpenVPN plugin
add_library(openvpn_auth_plugin SHARED
  cpp-openvpn-plugin/src/plugin.cpp
  cpp-openvpn-plugin/src/config.cpp
)

target_include_directories(openvpn_auth_plugin PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/cpp-openvpn-plugin/src
  ${OPENVPN_PLUGIN_INCLUDE_DIR}
)

target_link_libraries(openvpn_auth_plugin
  PRIVATE
    common_headers
    spdlog::spdlog
    yaml-cpp
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${HTTPLIB_TARGET}
    nlohmann_json::nlohmann_json
)

target_compile_definitions(openvpn_auth_plugin PRIVATE HTTPLIB_OPENSSL_SUPPORT)
set_target_properties(openvpn_auth_plugin PROPERTIES
  PREFIX "lib"
  OUTPUT_NAME "openvpn_auth_plugin"
)

# Radius client
add_executable(radius-client
  cpp-radius-client/src/main.cpp
)

target_link_libraries(radius-client
  PRIVATE
    common_headers
    OpenSSL::SSL
    OpenSSL::Crypto
)
