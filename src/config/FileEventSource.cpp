// FileEventSource.cpp
#include "config/FileEventSource.h"
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>

FileEventSource::FileEventSource(const std::string& filePath)
    : m_filePath(filePath), m_isRunning(false) {
}

FileEventSource::~FileEventSource() {
    stop(); // Đảm bảo luồng dừng khi hủy
    if (m_inotifyFd >= 0) {
        if (m_watchFd >= 0) {
             inotify_rm_watch(m_inotifyFd, m_watchFd);
        }
        close(m_inotifyFd);
    }
    if (m_eventFd >= 0) {
        close(m_eventFd);
    }
}

void FileEventSource::setCallback(std::function<void(const std::string&)> callback) {
    m_callback = callback;
}

bool FileEventSource::start() {
    if (m_isRunning) return true; // Đã chạy rồi

    // 1. Kiểm tra callback
    if (!m_callback) {
        std::cerr << "FileEventSource Error: Callback chưa được set." << std::endl;
        return false;
    }

    // 2. Khởi tạo inotify
    m_inotifyFd = inotify_init1(IN_NONBLOCK);
    if (m_inotifyFd < 0) {
        std::cerr << "FileEventSource Error: Failed to initialize inotify" << std::endl;
        return false; // Thất bại, không ảnh hưởng main thread
    }

    // 3. Thêm file vào watch
    m_watchFd = inotify_add_watch(m_inotifyFd, m_filePath.c_str(), IN_CLOSE_WRITE);
    if (m_watchFd < 0) {
        std::cerr << "FileEventSource Error: Failed to add inotify watch for: " << m_filePath << std::endl;
        close(m_inotifyFd);
        m_inotifyFd = -1;
        return false; // Thất bại, không ảnh hưởng main thread
    }

    // 4. Tạo eventfd
    m_eventFd = eventfd(0, EFD_NONBLOCK);
    if (m_eventFd < 0) {
        std::cerr << "FileEventSource Error: Failed to create eventfd" << std::endl;
        inotify_rm_watch(m_inotifyFd, m_watchFd);
        close(m_inotifyFd);
        return false; // Thất bại, không ảnh hưởng main thread
    }

    // 5. Mọi thứ OK, bắt đầu luồng
    m_isRunning = true;
    m_listenerThread = std::thread(&FileEventSource::run, this);
    std::cout << "FileEventSource started for: " << m_filePath << std::endl;
    return true; // Bắt đầu thành công
}

void FileEventSource::stop() {
    if (!m_isRunning.exchange(false)) {
        return; // Đã dừng rồi
    }

    std::cout << "Stopping FileEventSource..." << std::endl;

    if (m_eventFd >= 0) {
        uint64_t val = 1;
        write(m_eventFd, &val, sizeof(val));
    }

    if (m_listenerThread.joinable()) {
        m_listenerThread.join();
    }
    std::cout << "FileEventSource stopped." << std::endl;
}

void FileEventSource::run() {
    struct pollfd fds[2];
    fds[0].fd = m_inotifyFd;
    fds[0].events = POLLIN;
    fds[1].fd = m_eventFd;
    fds[1].events = POLLIN;

    char buffer[4096];

    while (m_isRunning) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            std::cerr << "FileEventSource poll() error" << std::endl;
            continue;
        }

        if (fds[1].revents & POLLIN) {
            break; // Tín hiệu dừng
        }

        if (fds[0].revents & POLLIN) {
            int length = read(m_inotifyFd, buffer, sizeof(buffer));
            if (length < 0) continue;

            std::ifstream file(m_filePath);
            if (!file.is_open()) continue;

            std::string line;
            if (std::getline(file, line) && !line.empty()) {
                // *** GỌI CALLBACK ***
                // Gửi tin nhắn thô cho ConfigManager xử lý
                try {
                     m_callback(line);
                } catch (const std::exception& e) {
                    std::cerr << "Exception in event callback: " << e.what() << std::endl;
                }
            }
            file.close();
        }
    }
}