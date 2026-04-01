#pragma once

#include <memory>
#include <string>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stderr_color_sinks.h>

namespace common {

inline spdlog::level::level_enum parse_level(const std::string& level) {
  std::string l = level;
  for (auto& c : l) c = static_cast<char>(::toupper(c));
  if (l == "DEBUG") return spdlog::level::debug;
  if (l == "INFO") return spdlog::level::info;
  if (l == "WARN" || l == "WARNING") return spdlog::level::warn;
  if (l == "ERROR") return spdlog::level::err;
  return spdlog::level::info;
}

inline std::shared_ptr<spdlog::logger> make_logger(const std::string& name,
                                                   const std::string& file,
                                                   const std::string& level) {
  auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file, true);
  auto err_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();

  // Errors go to stderr, everything goes to file.
  err_sink->set_level(spdlog::level::err);
  file_sink->set_level(parse_level(level));

  auto logger = std::make_shared<spdlog::logger>(name, spdlog::sinks_init_list{err_sink, file_sink});
  logger->set_level(parse_level(level));
  logger->set_pattern("%Y-%m-%dT%H:%M:%S.%e%z [%n] [%l] [pid:%P tid:%t] %v");
  logger->flush_on(spdlog::level::warn);
  spdlog::register_logger(logger);
  return logger;
}

} // namespace common
