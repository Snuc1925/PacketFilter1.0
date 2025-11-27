// RateLimit.cpp
#include "MapFdManager.h"
#include <iostream>
#include "config/type/RateLimit.h"
#include "types.h"
#include <bpf/bpf.h>

#include <sstream>
#include <arpa/inet.h>
#include <cerrno>
#include <string.h>
#include <fstream>
#include <string>
#include "Constants.h"

RateLimit::~RateLimit() {
    std::cout << "Destroying RateLimit...\n";
}

bool RateLimit::loadConfig() {
    // Get map FDs
    map_fd_rate_limits = MapFdManager::getInstance().get_map_fd_by_name("ip_rate_limits_map");
    if (map_fd_rate_limits < 0) {
        std::cerr << "Failed to get FD for ip_rate_limits_map\n";
        return false;
    }

    map_fd_config_state = MapFdManager::getInstance().get_map_fd_by_name("config_state_map");
    if (map_fd_config_state < 0) {
        std::cerr << "Failed to get FD for config_state_map\n";
        return false;
    }

    const std::string path = Constants::DEFAULT_CONFIG_RATELIMIT();
    std::ifstream config_file(path);
    if (!config_file.is_open()) {
        std::cerr << "Warning: Failed to open ratelimit config file: " << path << std::endl;
        // Not a critical error - ratelimit might not be configured
        return true;
    }

    std::string line;
    bool first_line = true;

    while (std::getline(config_file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        if (first_line) {
            first_line = false;
            if (line == "disabled") {
                std::cout << "Loading config: RateLimit is disabled." << std::endl;
                config_file.close();
                return disable_ratelimit();
            }

            std::cout << "Loading config: RateLimit is enabled." << std::endl;
            if (!enable_ratelimit()) {
                std::cerr << "Failed to set enabled state during load." << std::endl;
                config_file.close();
                return false;
            }
        }

        if (line == "enabled" || line == "disabled") {
            continue;
        }

        // Format: "add <ip> <packets_per_second>" or just "<ip> <packets_per_second>"
        std::string command_line = line;
        if (line.find("add ") != 0 && line.find("remove ") != 0) {
            command_line = "add " + line;
        }
        
        if (!updateConfig(command_line)) {
            std::cerr << "Warning: Failed to process config line: '" << line << "'" << std::endl;
        }
    }

    config_file.close();
    
    if (first_line) {
        std::cout << "Config file is empty. Defaulting ratelimit to disabled." << std::endl;
        return disable_ratelimit();
    }
    
    return true;
}

// Format: "add <ip> <packets_per_second>" or "remove <ip>" or "enabled" or "disabled"
bool RateLimit::updateConfig(const std::string& message) {
    std::cout << "Updating ratelimit config with message: " << message << "\n";

    std::stringstream ss(message);
    std::string command;
    ss >> command;

    if (command == "enabled") {
        return enable_ratelimit();
    }

    if (command == "disabled") {
        return disable_ratelimit();
    }

    std::string ip_str;
    ss >> ip_str;

    if (ip_str.empty()) {
        std::cerr << "Missing IP address for command: " << command << std::endl;
        return false;
    }

    // Parse IP address
    uint32_t ip;
    if (inet_pton(AF_INET, ip_str.c_str(), &ip) != 1) {
        std::cerr << "Invalid IP address format: " << ip_str << std::endl;
        return false;
    }

    if (command == "add") {
        uint32_t packets_per_second;
        ss >> packets_per_second;
        
        if (ss.fail() || packets_per_second == 0) {
            std::cerr << "Invalid or missing packets_per_second value" << std::endl;
            return false;
        }
        
        return add_rate_limit(ip, packets_per_second);
    }

    if (command == "remove") {
        return remove_rate_limit(ip);
    }

    std::cerr << "Unknown command: " << command << std::endl;
    return false;
}

bool RateLimit::add_rate_limit(uint32_t ip, uint32_t packets_per_second) {
    IPRateLimitConfig config;
    config.packets_per_second = packets_per_second;
    // Calculate interval in nanoseconds: 1 second = 1,000,000,000 ns
    config.packet_interval_ns = 1000000000ULL / packets_per_second;
    
    std::cout << "Adding rate limit for IP (fd=" << map_fd_rate_limits << "): " 
              << packets_per_second << " pps (interval: " 
              << config.packet_interval_ns << " ns)\n";
              
    if (bpf_map_update_elem(map_fd_rate_limits, &ip, &config, BPF_ANY) != 0) {
        std::cerr << "Failed to update rate limit map: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool RateLimit::remove_rate_limit(uint32_t ip) {
    if (bpf_map_delete_elem(map_fd_rate_limits, &ip) != 0) {
        if (errno != ENOENT) {
            std::cerr << "Failed to delete from rate limit map: " << strerror(errno) << std::endl;
            return false;
        }
    }
    return true;
}

bool RateLimit::disable_ratelimit() {
    uint32_t key = 1; // Key 1 is for ratelimit
    uint8_t value = 0; // 0 = disabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to disable ratelimit: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "RateLimit disabled.\n";
    return true;
}

bool RateLimit::enable_ratelimit() {
    uint32_t key = 1; // Key 1 is for ratelimit
    uint8_t value = 1; // 1 = enabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to enable ratelimit: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "RateLimit enabled.\n";
    return true;
}
