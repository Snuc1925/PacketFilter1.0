// Whitelist.cpp
#include "MapFdManager.h"
#include <iostream>
#include "config/type/Whitelist.h"
#include "types.h"
#include <bpf/bpf.h>

#include <sstream>
#include <arpa/inet.h>
#include <cerrno>
#include <string.h>
#include <fstream>
#include <string>
#include "Constants.h"

// Helper function to parse subnet string (e.g., "192.168.1.0/24")
static bool parse_subnet(const std::string& subnet_str, IPSubnet& subnet) {
    size_t slash_pos = subnet_str.find('/');
    if (slash_pos == std::string::npos) {
        std::cerr << "Invalid subnet format (missing '/'): " << subnet_str << std::endl;
        return false;
    }

    std::string ip_str = subnet_str.substr(0, slash_pos);
    std::string prefix_str = subnet_str.substr(slash_pos + 1);

    if (inet_pton(AF_INET, ip_str.c_str(), &subnet.ip) != 1) {
        std::cerr << "Invalid IP address format: " << ip_str << std::endl;
        return false;
    }

    try {
        subnet.prefixlen = std::stoul(prefix_str);
        if (subnet.prefixlen > 32) {
            std::cerr << "Invalid prefix length (must be 0-32): " << subnet.prefixlen << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Invalid prefix length (not a number): " << prefix_str << std::endl;
        return false;
    }

    return true;
}

Whitelist::~Whitelist() {
    std::cout << "Destroying Whitelist...\n";
}

bool Whitelist::loadConfig() {
    // Get map FDs
    map_fd_whitelist_subnets = MapFdManager::getInstance().get_map_fd_by_name("whitelist_subnets_map");
    if (map_fd_whitelist_subnets < 0) {
        std::cerr << "Failed to get FD for whitelist_subnets_map\n";
        return false;
    }

    map_fd_config_state = MapFdManager::getInstance().get_map_fd_by_name("config_state_map");
    if (map_fd_config_state < 0) {
        std::cerr << "Failed to get FD for config_state_map\n";
        return false;
    }

    const std::string path = Constants::DEFAULT_CONFIG_WHITELIST();
    std::ifstream config_file(path);
    if (!config_file.is_open()) {
        std::cerr << "Warning: Failed to open whitelist config file: " << path << std::endl;
        // Not a critical error - whitelist might not be configured
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
                std::cout << "Loading config: Whitelist is disabled." << std::endl;
                config_file.close();
                return disable_whitelist();
            }

            std::cout << "Loading config: Whitelist is enabled." << std::endl;
            if (!enable_whitelist()) {
                std::cerr << "Failed to set enabled state during load." << std::endl;
                config_file.close();
                return false;
            }
        }

        if (line == "enabled" || line == "disabled") {
            continue;
        }

        std::string command_line = "add " + line;
        if (!updateConfig(command_line)) {
            std::cerr << "Warning: Failed to process config line: '" << line << "'" << std::endl;
        }
    }

    config_file.close();
    
    if (first_line) {
        std::cout << "Config file is empty. Defaulting whitelist to disabled." << std::endl;
        return disable_whitelist();
    }
    
    return true;
}

bool Whitelist::updateConfig(const std::string& message) {
    std::cout << "Updating whitelist config with message: " << message << "\n";

    std::stringstream ss(message);
    std::string command;
    ss >> command;

    if (command == "enabled") {
        return enable_whitelist();
    }

    if (command == "disabled") {
        return disable_whitelist();
    }

    std::string subnet_str;
    ss >> subnet_str;

    if (subnet_str.empty()) {
        std::cerr << "Missing subnet for command: " << command << std::endl;
        return false;
    }

    IPSubnet subnet_key;
    if (!parse_subnet(subnet_str, subnet_key)) {
        return false;
    }

    if (command == "add") {
        return add_ip_subnets(&subnet_key);
    }

    if (command == "remove") {
        return remove_ip_subnets(&subnet_key);
    }

    std::cerr << "Unknown command: " << command << std::endl;
    return false;
}

bool Whitelist::add_ip_subnets(IPSubnet *key) {
    uint8_t value = 1;
    std::cout << "Adding to whitelist_subnets_map fd=" << map_fd_whitelist_subnets << "...\n";
    if (bpf_map_update_elem(map_fd_whitelist_subnets, key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to update whitelist subnet map: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool Whitelist::remove_ip_subnets(IPSubnet *key) {
    if (bpf_map_delete_elem(map_fd_whitelist_subnets, key) != 0) {
        if (errno != ENOENT) {
            std::cerr << "Failed to delete from whitelist subnet map: " << strerror(errno) << std::endl;
            return false;
        }
    }
    return true;
}

bool Whitelist::disable_whitelist() {
    uint32_t key = ConfigKey::WHITELIST;
    uint8_t value = 0; // 0 = disabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to disable whitelist: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "Whitelist disabled.\n";
    return true;
}

bool Whitelist::enable_whitelist() {
    uint32_t key = ConfigKey::WHITELIST;
    uint8_t value = 1; // 1 = enabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to enable whitelist: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "Whitelist enabled.\n";
    return true;
}
