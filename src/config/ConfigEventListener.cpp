// ConfigEventListener.cpp
#include "config/ConfigEventListener.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>     // Cho read, close
#include <poll.h>       // Cho poll
#include <sys/inotify.h> // Cho inotify
#include <sys/eventfd.h>  // Cho eventfd

ConfigEventListener::ConfigEventListener(const std::string& filePath,
                                     std::vector<std::unique_ptr<ConfigType>>& configTypes)
    : m_filePath(filePath),
      m_configTypes(configTypes),
      m_isRunning(false) {
    
    // 1. Khởi tạo inotify
    m_inotifyFd = inotify_init1(IN_NONBLOCK);
    if (m_inotifyFd < 0) {
        std::cerr << "Failed to initialize inotify" << std::endl;
        // Xử lý lỗi
    }

    // 2. Thêm file vào watch
    // Chúng ta theo dõi IN_CLOSE_WRITE (khi file được ghi xong và đóng lại)
    m_watchFd = inotify_add_watch(m_inotifyFd, m_filePath.c_str(), IN_CLOSE_WRITE);
    if (m_watchFd < 0) {
        std::cerr << "Failed to add inotify watch for: " << m_filePath << std::endl;
        // Xử lý lỗi
    }

    // 3. Tạo eventfd để có thể ngắt poll() khi stop()
    m_eventFd = eventfd(0, EFD_NONBLOCK);
    if (m_eventFd < 0) {
        std::cerr << "Failed to create eventfd" << std::endl;
        // Xử lý lỗi
    }
}

ConfigEventListener::~ConfigEventListener() {
    stop(); // Đảm bảo luồng dừng khi hủy
    if (m_inotifyFd >= 0) {
        inotify_rm_watch(m_inotifyFd, m_watchFd);
        close(m_inotifyFd);
    }
    if (m_eventFd >= 0) {
        close(m_eventFd);
    }
}

void ConfigEventListener::start() {
    if (m_isRunning) return; // Chỉ chạy một lần

    m_isRunning = true;
    m_listenerThread = std::thread(&ConfigEventListener::run, this);
    std::cout << "Config event listener started for: " << m_filePath << std::endl;
}

void ConfigEventListener::stop() {
    if (!m_isRunning.exchange(false)) {
        return; // Đã dừng rồi
    }

    std::cout << "Stopping config event listener..." << std::endl;

    // Ghi vào eventfd để đánh thức poll()
    if (m_eventFd >= 0) {
        uint64_t val = 1;
        write(m_eventFd, &val, sizeof(val));
    }

    // Chờ luồng kết thúc
    if (m_listenerThread.joinable()) {
        m_listenerThread.join();
    }
    std::cout << "Config event listener stopped." << std::endl;
}

void ConfigEventListener::run() {
    struct pollfd fds[2];
    fds[0].fd = m_inotifyFd;
    fds[0].events = POLLIN;

    fds[1].fd = m_eventFd;
    fds[1].events = POLLIN;

    char buffer[4096]; // Buffer cho sự kiện inotify

    while (m_isRunning) {
        // Chờ sự kiện (từ inotify hoặc eventfd)
        int ret = poll(fds, 2, -1); // Chờ vô hạn
        if (ret < 0) {
            std::cerr << "poll() error" << std::endl;
            continue;
        }

        // 1. Kiểm tra xem có phải tín hiệu stop không
        if (fds[1].revents & POLLIN) {
            // Sự kiện từ eventfd -> dừng luồng
            break;
        }

        // 2. Kiểm tra xem có phải sự kiện file không
        if (fds[0].revents & POLLIN) {
            // Đọc sự kiện inotify
            int length = read(m_inotifyFd, buffer, sizeof(buffer));
            if (length < 0) {
                std::cerr << "inotify read error" << std::endl;
                continue;
            }

            // Đọc nội dung file
            std::ifstream file(m_filePath);
            if (!file.is_open()) {
                std::cerr << "Failed to open event file: " << m_filePath << std::endl;
                continue;
            }

            std::string line;
            if (std::getline(file, line)) {
                if (!line.empty()) {
                    processMessage(line);
                }
            }
            file.close();

            // Xóa trắng file sau khi đọc (TÙY CHỌN)
            // Nếu bạn muốn file này hoạt động như một "hàng đợi",
            // bạn có thể xóa nội dung của nó sau khi đọc.
            // std::ofstream ofs(m_filePath, std::ofstream::trunc);
            // ofs.close();
        }
    }
}

void ConfigEventListener::processMessage(const std::string& line) {
    std::cout << "Processing message: " << line << std::endl;

    // Tách chuỗi bằng dấu ":"
    size_t delimiterPos = line.find(':');
    if (delimiterPos == std::string::npos) {
        std::cerr << "Invalid message format (missing ':'): " << line << std::endl;
        return;
    }

    std::string configTypeStr = line.substr(0, delimiterPos);
    std::string message = line.substr(delimiterPos + 1);

    // Trim khoảng trắng
    configTypeStr.erase(0, configTypeStr.find_first_not_of(" \t\n\r"));
    configTypeStr.erase(configTypeStr.find_last_not_of(" \t\n\r") + 1);
    message.erase(0, message.find_first_not_of(" \t\n\r"));
    message.erase(message.find_last_not_of(" \t\n\r") + 1);

    // Tìm ConfigType tương ứng
    bool found = false;
    for (const auto& config : m_configTypes) {
        if (config->getTypeName() == configTypeStr) {
            std::cout << "Dispatching to " << configTypeStr << " with message: " << message << std::endl;
            if (!config->updateConfig(message)) {
                std::cerr << "Failed to update config for " << configTypeStr << std::endl;
            }
            found = true;
            break;
        }
    }

    if (!found) {
        std::cerr << "No config handler found for type: " << configTypeStr << std::endl;
    }
}