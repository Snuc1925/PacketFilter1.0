#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include "packetfilter.skel.h" // Chứa định nghĩa packetfilter_bpf

class MapFdManager {
public:
    // Xóa copy constructor và copy assignment operator
    MapFdManager(const MapFdManager&) = delete;
    MapFdManager& operator=(const MapFdManager&) = delete;

    ~MapFdManager();

    /**
     * @brief Khởi tạo Singleton. Phải được gọi một lần duy nhất.
     * @param skel Con trỏ duy nhất đến eBPF skeleton đã được load.
     */
    static void initialize(std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel);

    /**
     * @brief Lấy tham chiếu đến instance duy nhất của MapFdManager.
     * @return Một tham chiếu đến instance.
     * @throws std::runtime_error nếu chưa được khởi tạo.
     */
    static MapFdManager& getInstance();

    // Các hàm thành viên khác vẫn giữ nguyên
    int get_map_fd_by_name(const std::string& name);

private:
    /**
     * @brief Constructor là private để ngăn tạo instance trực tiếp.
     */
    MapFdManager(std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel_);

    // Con trỏ tĩnh đến instance duy nhất
    static std::unique_ptr<MapFdManager> instance;

    // Các biến thành viên
    std::unique_ptr<packetfilter_bpf, void(*)(packetfilter_bpf*)> skel;
    std::unordered_map<std::string, int> map_fd_table;
};