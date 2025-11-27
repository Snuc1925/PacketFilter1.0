#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string>

namespace Constants {
    inline constexpr const char* DEFAULT_CONFIG_DIR = "/etc/ebpf";

    inline std::string DEFAULT_CONFIG_BLACKLIST() {
        return std::string(DEFAULT_CONFIG_DIR) + "/blacklist.conf";
    }

    inline std::string DEFAULT_CONFIG_RATELIMIT() {
        return std::string(DEFAULT_CONFIG_DIR) + "/ratelimit.conf";
    }

    inline std::string DEFAULT_CONFIG_WHITELIST() {
        return std::string(DEFAULT_CONFIG_DIR) + "/whitelist.conf";
    }

    inline std::string DEFAULT_CONFIG_INTERFACE() {
        return std::string(DEFAULT_CONFIG_DIR) + "/interface.conf";
    }

    inline std::string DEFAULT_CONFIG_EVENT_LISTENER() {
        return std::string(DEFAULT_CONFIG_DIR) + "/event.conf";
    }

    inline constexpr const char* DEFAULT_LOG_DIR = "/var/log/ebpf";

    inline std::string DEFAULT_LOG_ACCESS() {
        return std::string(DEFAULT_LOG_DIR) + "/access.log";
    }

    // Log buffer settings
    inline constexpr size_t DEFAULT_LOG_ACCESS_BUFFER_SIZE = 100;
    inline constexpr int DEFAULT_LOG_ACCESS_TIMEOUT_MS = 1000;
}

#endif
