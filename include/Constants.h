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

    inline std::string DEFAULT_CONFIG_INTERFACE() {
        return std::string(DEFAULT_CONFIG_DIR) + "/interface.conf";
    }

    inline constexpr const char* DEFAULT_LOG_DIR = "/var/log/ebpf";
}

#endif
