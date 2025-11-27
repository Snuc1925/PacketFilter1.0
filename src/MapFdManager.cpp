#include "MapFdManager.h"
#include <iostream>
#include <stdexcept>

// Initialize static pointer
std::unique_ptr<MapFdManager> MapFdManager::instance = nullptr;

MapFdManager::MapFdManager(std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel_)
    : skel(std::move(skel_))
{
    // Load blacklist_subnets_map
    int fd_blacklist = bpf_map__fd(skel->maps.blacklist_subnets_map);
    if (fd_blacklist < 0)
        std::cerr << "Warning: Failed to get FD for blacklist_subnets_map\n";
    else {
        map_fd_table["blacklist_subnets_map"] = fd_blacklist;
        std::cout << "Load blacklist_subnets_map successfully...\n";
    }

    // Load whitelist_subnets_map
    int fd_whitelist = bpf_map__fd(skel->maps.whitelist_subnets_map);
    if (fd_whitelist < 0)
        std::cerr << "Warning: Failed to get FD for whitelist_subnets_map\n";
    else {
        map_fd_table["whitelist_subnets_map"] = fd_whitelist;
        std::cout << "Load whitelist_subnets_map successfully...\n";
    }

    // Load config_state_map
    int fd_config = bpf_map__fd(skel->maps.config_state_map);
    if (fd_config < 0)
        std::cerr << "Warning: Failed to get FD for config_state_map\n";
    else {
        map_fd_table["config_state_map"] = fd_config;
        std::cout << "Load config_state_map successfully...\n";
    }

    // Load ip_rate_limits_map
    int fd_rate_limits = bpf_map__fd(skel->maps.ip_rate_limits_map);
    if (fd_rate_limits < 0)
        std::cerr << "Warning: Failed to get FD for ip_rate_limits_map\n";
    else {
        map_fd_table["ip_rate_limits_map"] = fd_rate_limits;
        std::cout << "Load ip_rate_limits_map successfully...\n";
    }

    // Load packet_ringbuf
    int fd_ringbuf = bpf_map__fd(skel->maps.packet_ringbuf);
    if (fd_ringbuf < 0)
        std::cerr << "Warning: Failed to get FD for packet_ringbuf\n";
    else {
        map_fd_table["packet_ringbuf"] = fd_ringbuf;
        std::cout << "Load packet_ringbuf successfully...\n";
    }
}

MapFdManager::~MapFdManager() {
    std::cout << "Destroying MapFdManager singleton instance...\n";
}

// --- Các hàm static mới ---

void MapFdManager::initialize(std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel) {
    if (instance) {
        // Có thể throw exception hoặc log warning nếu muốn
        std::cerr << "Warning: MapFdManager already initialized.\n";
        return;
    }
    // Dùng new và reset vì make_unique không thể gọi constructor private
    // Hàm static của class có thể truy cập constructor private
    instance.reset(new MapFdManager(std::move(skel)));
}

MapFdManager& MapFdManager::getInstance() {
    if (!instance) {
        throw std::runtime_error("MapFdManager has not been initialized. Call initialize() first.");
    }
    return *instance;
}


// --- Hàm thành viên cũ (logic không đổi) ---
int MapFdManager::get_map_fd_by_name(const std::string& name) {
    auto it = map_fd_table.find(name);
    if (it == map_fd_table.end()) {
        std::cerr << "Error: Unknown map name '" << name << "'\n";
        return -1;
    }

    int fd = it->second;
    if (fd < 0) {
        std::cerr << "Error: Invalid FD for map '" << name << "'\n";
        return -1;
    }

    std::cout << "Get map fd successfully for " << name << "...\n";

    return fd;
}