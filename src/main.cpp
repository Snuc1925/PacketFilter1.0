#include <iostream>
#include "config/ConfigManager.h"
#include "MapFdManager.h"
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <bpf/libbpf.h>
#include <csignal>
#include "packetfilter.skel.h" 
#include "logger/AccessLogWriter.h"
#include <atomic>
#include <memory>
#include <spdlog/async.h>

std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nCaught signal " << signum << ", exiting...\n";
    running = false; 
}

// Load eBPF program
std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> load_ebpf_program() {
    std::cout << "Loading eBPF program..." << std::endl;

    std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel(
        packetfilter_bpf__open_and_load(),
        [](packetfilter_bpf* s) {
            if (s) {
                std::cout << "Destroying eBPF skeleton..." << std::endl;
                packetfilter_bpf__destroy(s);
            }
        }
    );

    if (!skel) {
        std::cerr << "Failed to open and load BPF skeleton." << std::endl;
        return {nullptr, [](packetfilter_bpf*) {}};
    }

    std::cout << "eBPF program loaded successfully." << std::endl;
    return skel;
}

// Attach vào interface
std::unique_ptr<bpf_link, void(*)(bpf_link*)> attach_ebpf_interface(packetfilter_bpf* skel, const std::string& interface) {
    std::cout << "Attaching eBPF to interface: " << interface << std::endl;

    uint32_t ifindex = if_nametoindex(interface.c_str());
    if (!ifindex) {
        std::cerr << "if_nametoindex error: " << strerror(errno) << std::endl;
        return {nullptr, [](bpf_link*) {}};
    }

    std::unique_ptr<bpf_link, void(*)(bpf_link*)> link(
        bpf_program__attach_xdp(skel->progs.xdp_filter, ifindex),
        [](bpf_link* l) {
            if (l) {
                std::cout << "Detaching eBPF program..." << std::endl;
                bpf_link__destroy(l);
            }
        }
    );

    if (!link) {
        std::cerr << "Failed to attach XDP program to " << interface << std::endl;
        return {nullptr, [](bpf_link*) {}};
    }

    std::cout << "Attached successfully to " << interface << " (index " << ifindex << ")" << std::endl;
    return link;
}

int main() {
    std::signal(SIGINT, signal_handler);    
    ConfigManager configManager;
    std::string interface;

    try {
        interface = configManager.getInterface();
        std::cout << "Interface: " << interface << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    auto skel = load_ebpf_program();
    if (!skel) return 1;

    auto link = attach_ebpf_interface(skel.get(), interface);
    if (!link) return 1;

    // auto mapFdManager = std::make_shared<MapFdManager>(std::move(skel));
    MapFdManager::initialize(std::move(skel));

    configManager.loadAllConfigs();
    configManager.startEventListener();

    std::cout << "Program running... Press Ctrl+C to exit.\n";


    // ------------------------------
    // TẠO CÁC LOG WRITER
    // ------------------------------

    // Ví dụ: Access log writer
    auto accessWriter = std::make_shared<AccessLogWriter>();

    // Nếu bạn thêm nhiều log:
    // auto dropWriter = std::make_shared<DropLogWriter>();
    // auto alertWriter = std::make_shared<AlertLogWriter>();
    // auto perfWriter = std::make_shared<PerformanceLogWriter>();

    // ------------------------------
    // START LISTENER CHO TỪNG LOG WRITER
    // Điều này tạo thread riêng để đọc ring-buffer
    // ------------------------------

// --- BẮT BUỘC PHẢI CÓ DÒNG NÀY ĐẦU TIÊN ---
    // 8192: Kích thước hàng đợi (Queue size). Nếu log quá nhanh đầy hàng đợi này thì log cũ có thể bị drop.
    // 1: Số lượng thread nền để ghi log (thường là 1 là đủ).
    spdlog::init_thread_pool(8192, 1); 
    // ------------------------------------------
    

    accessWriter->startLogListener();
    // dropWriter->startLogListener();
    // alertWriter->startLogListener();

    // ------------------------------    

    while (running) {
        sleep(1);
    }

    spdlog::shutdown();

    std::cout << "Exiting program...\n";
    return 0;
}