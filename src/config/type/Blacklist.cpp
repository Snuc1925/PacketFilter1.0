// Blacklist.cpp
#include "MapFdManager.h"
#include <iostream>
#include "config/type/Blacklist.h"
#include "types.h"
#include <bpf/bpf.h>

// Thêm các include cần thiết
#include <sstream>      // Để phân tích chuỗi message
#include <arpa/inet.h>  // Để dùng inet_pton
#include <cerrno>       // Để dùng errno
#include <string.h>     // Để dùng strerror
#include <fstream>      // --- THÊM VÀO: Để đọc file (std::ifstream)
#include <string>       // --- THÊM VÀO: Để xử lý dòng (std::string, std::getline)
#include "Constants.h"   // --- THÊM VÀO: Để lấy hằng số DEFAULT_CONFIG_BLACKLIST

// ---- HÀM HỖ TRỢ ----
// (Giữ nguyên hàm parse_subnet)
bool parse_subnet(const std::string& subnet_str, IPSubnet& subnet) {
    size_t slash_pos = subnet_str.find('/');
    if (slash_pos == std::string::npos) {
        std::cerr << "Định dạng subnet không hợp lệ (thiếu '/'): " << subnet_str << std::endl;
        return false;
    }

    std::string ip_str = subnet_str.substr(0, slash_pos);
    std::string prefix_str = subnet_str.substr(slash_pos + 1);

    // Phân tích địa chỉ IP
    if (inet_pton(AF_INET, ip_str.c_str(), &subnet.ip) != 1) {
        std::cerr << "Định dạng địa chỉ IP không hợp lệ: " << ip_str << std::endl;
        return false;
    }
    // Chú ý: inet_pton lưu IP ở định dạng network byte order.
    // Nếu map BPF của bạn cần host byte order, bạn cần dùng ntohl().
    // Giả sử network byte order là đúng.

    // Phân tích prefixlen
    try {
        subnet.prefixlen = std::stoul(prefix_str);
        if (subnet.prefixlen > 32) {
            std::cerr << "Prefix length không hợp lệ (phải từ 0-32): " << subnet.prefixlen << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Prefix length không hợp lệ (không phải là số): " << prefix_str << std::endl;
        return false;
    }

    return true;
}
// ---- KẾT THÚC HÀM HỖ TRỢ ----


Blacklist::~Blacklist() {
    std::cout << "Destroying Blacklist...\n";
}

bool Blacklist::loadConfig() {
    // 1. Lấy map FDs
    map_fd_blacklist_subnets = MapFdManager::getInstance().get_map_fd_by_name("blacklist_subnets_map");
    if (map_fd_blacklist_subnets < 0) {
        std::cerr << "Failed to get FD for blacklist_subnets_map\n";
        return false;
    }

    map_fd_config_state = MapFdManager::getInstance().get_map_fd_by_name("config_state_map");
    if (map_fd_config_state < 0) {
        std::cerr << "Failed to get FD for config_state_map\n";
        return false;
    }

    const std::string path = Constants::DEFAULT_CONFIG_BLACKLIST();
    // 2. Mở file cấu hình
    std::ifstream config_file(path);
    if (!config_file.is_open()) {
        std::cerr << "Error: Failed to open default config file: " 
                  << Constants::DEFAULT_CONFIG_BLACKLIST << std::endl;
        // Nếu không mở được file config, coi như thất bại
        return false;
    }

    std::string line;
    bool first_line = true;

    // 3. Đọc file
    while (std::getline(config_file, line)) {
        // Bỏ qua các dòng trống hoặc dòng comment (#)
        // (Bạn có thể thêm logic trim whitespace nếu cần)
        if (line.empty() || line[0] == '#') {
            continue;
        }

        if (first_line) {
            first_line = false;
            if (line == "disabled") {
                std::cout << "Loading config: Blacklist is disabled." << std::endl;
                config_file.close();
                // Theo yêu cầu: gọi disable_blacklist() và return
                return disable_blacklist();
            }

            // Nếu không phải "disabled", mặc định là "enabled"
            std::cout << "Loading config: Blacklist is enabled." << std::endl;
            if (!enable_blacklist()) {
                std::cerr << "Failed to set default enabled state during load." << std::endl;
                config_file.close();
                return false;
            }
            
            // Nếu dòng đầu tiên không phải "disabled",
            // nó có thể là một lệnh (ví dụ: "add ..."),
            // nên chúng ta *không* 'continue', mà để nó được xử lý bên dưới.
        }

        // 4. Xử lý các dòng (bao gồm cả dòng đầu tiên nếu nó không phải "disabled")
        // Bỏ qua các dòng "enabled" hoặc "disabled" (nếu không phải dòng đầu)
        if (line == "enabled" || line == "disabled") {
            continue;
        }

        // TẠO DÒNG MỚI VỚI LỆNH "add"
        // Vì các dòng còn lại chỉ chứa subnet (ví dụ: "192.168.78.100/32"),
        // ta cần thêm tiền tố "add " để hàm updateConfig có thể xử lý.
        std::string command_line = "add " + line;

        // Tái sử dụng hàm updateConfig để phân tích và áp dụng
        // các lệnh "add" hoặc "remove"
        if (!updateConfig(command_line)) {
            // Ghi log cảnh báo nhưng tiếp tục xử lý các dòng khác
            std::cerr << "Warning: Failed to process config line: '" << line << "'" << std::endl;
        }
    }

    config_file.close();
    
    // Nếu file trống, 'first_line' vẫn là true.
    // Chúng ta cần đảm bảo state là "enabled"
    if (first_line) {
        std::cout << "Config file is empty. Defaulting to enabled." << std::endl;
        return enable_blacklist();
    }
    
    return true;
}

// add 192.168.100.0/32 
// disabled
// enabled
// remove 192.168.100.0/32
bool Blacklist::updateConfig(const std::string& message) {
    std::cout << "Updating blacklist config with message: " << message << "\n";

    std::stringstream ss(message);
    std::string command;
    ss >> command; // Đọc từ đầu tiên (add, remove, enabled, disabled)

    if (command == "enabled") {
        return enable_blacklist();
    }

    if (command == "disabled") {
        return disable_blacklist();
    }

    // Nếu không phải 'enabled' hay 'disabled', thì phải là 'add' hoặc 'remove'
    // và cần có thêm một tham số là subnet
    std::string subnet_str;
    ss >> subnet_str;

    if (subnet_str.empty()) {
        std::cerr << "Thiếu subnet cho lệnh: " << command << std::endl;
        return false;
    }

    // Phân tích chuỗi subnet
    IPSubnet subnet_key;
    if (!parse_subnet(subnet_str, subnet_key)) {
        // Hàm parse_subnet đã in lỗi
        return false;
    }

    // Thực hiện lệnh
    if (command == "add") {
        return add_ip_subnets(&subnet_key);
    }

    if (command == "remove") {
        return remove_ip_subnets(&subnet_key);
    }

    std::cerr << "Lệnh không xác định: " << command << std::endl;
    return false;
}

bool Blacklist::add_ip_subnets(IPSubnet *key) {
    __u8 value = 1; // Giá trị placeholder, map này chỉ cần key
    std::cout << "Add to map_fd_blacklist_subnets " << map_fd_blacklist_subnets << "...\n";
    if (bpf_map_update_elem(map_fd_blacklist_subnets, key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to update blacklist subnet map: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool Blacklist::remove_ip_subnets(IPSubnet *key) {
    // SỬA LỖI: Phải dùng bpf_map_delete_elem để xóa
    if (bpf_map_delete_elem(map_fd_blacklist_subnets, key) != 0) {
        if (errno != ENOENT) { // ENOENT = No Such Entry, không phải lỗi thực sự
            std::cerr << "Failed to delete from blacklist subnet map: " << strerror(errno) << std::endl;
            return false;
        }
        // Nếu entry không tồn tại (ENOENT), cũng coi như thành công
    }
    return true;
}

bool Blacklist::disable_blacklist() {
    __u32 key = 0; // Key 0 là cho blacklist
    __u8 value = 0; // 0 = disabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to disable blacklist: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "Blacklist disabled.\n";
    return true;
}

bool Blacklist::enable_blacklist() {
    __u32 key = 0; // Key 0 là cho blacklist
    __u8 value = 1; // 1 = enabled
    if (bpf_map_update_elem(map_fd_config_state, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to enable blacklist: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "Blacklist enabled.\n";
    return true;
}