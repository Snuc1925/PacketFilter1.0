#include "config/ConfigManager.h"
#include "Constants.h"
#include "config/ConfigType.h"
#include "config/type/Blacklist.h"
#include <fstream>
#include <iostream>
#include <stdexcept>


// Đây là nơi duy nhất biết về FileEventSource
#include "config/FileEventSource.h"

ConfigManager::~ConfigManager() {
    std::cout << "Destroying ConfigManager...\n";
}

std::string ConfigManager::getInterface() {
    const std::string path = Constants::DEFAULT_CONFIG_INTERFACE();

    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file interface.conf at: " + path);
    }

    std::string interfaceName;
    std::getline(file, interfaceName);

    interfaceName.erase(interfaceName.find_last_not_of(" \n\r\t") + 1);

    if (interfaceName.empty()) {
        throw std::runtime_error("File interface.conf empty or unavailable");
    }

    return interfaceName;
}

bool ConfigManager::loadAllConfigs() {
    auto blacklist = std::make_unique<Blacklist>();
    if (!blacklist->loadConfig()) {
        std::cout << "Blacklist config load unsuccessful" << std::endl;
        return false;
    }

    configTypes.push_back(std::move(blacklist));

    std::cout << "Load configs sucessfully...\n";
    return true;
}

void ConfigManager::startEventListener() {
    if (m_eventSource) {
        std::cout << "Event listener already running." << std::endl;
        return;
    }
    
    // --- ĐÂY LÀ PHẦN LINH HOẠT ---
    // 1. Quyết định dùng source nào.
    // Trong tương lai, bạn có thể thay dòng này:
    // m_eventSource = std::make_unique<ConsulEventSource>(consul_address);
    m_eventSource = std::make_unique<FileEventSource>(
        Constants::DEFAULT_CONFIG_EVENT_LISTENER()
    );

    // 2. Đặt callback: Dùng lambda để "gói" hàm processEventMessage
    //    với con trỏ 'this' của ConfigManager.
    m_eventSource->setCallback(
        [this](const std::string& msg) {
            this->processEventMessage(msg);
        }
    );
    
    // 3. Bắt đầu và kiểm tra lỗi (NHƯ BẠN YÊU CẦU)
    if (!m_eventSource->start()) {
        // Nếu start() trả về false (ví dụ: file không tồn tại)
        std::cerr << "CRITICAL WARNING: Config event listener failed to start. "
                  << "Dynamic config updates will be DISABLED." << std::endl;
        
        // Hủy đối tượng đã thất bại
        m_eventSource.reset(); 
        
        // Luồng chính vẫn tiếp tục chạy
    } else {
        std::cout << "Config event listener started successfully." << std::endl;
    }
}

void ConfigManager::stopEventListener() {
    if (m_eventSource) {
        m_eventSource->stop();
        m_eventSource.reset();
    }
}

/**
 * @brief Hàm xử lý tin nhắn (chạy trên luồng của EventSource)
 */
void ConfigManager::processEventMessage(const std::string& line) {
    std::cout << "ConfigManager processing message: " << line << std::endl;

    size_t delimiterPos = line.find(':');
    if (delimiterPos == std::string::npos) {
        std::cerr << "Invalid message format (missing ':'): " << line << std::endl;
        return;
    }

    std::string configTypeStr = line.substr(0, delimiterPos);
    std::string message = line.substr(delimiterPos + 1);

    // Trim khoảng trắng (C++ 20 có hàm starts_with/ends_with, C++ 11 làm thủ công)
    configTypeStr.erase(0, configTypeStr.find_first_not_of(" \t\n\r"));
    configTypeStr.erase(configTypeStr.find_last_not_of(" \t\n\r") + 1);
    message.erase(0, message.find_first_not_of(" \t\n\r"));
    message.erase(message.find_last_not_of(" \t\n\r") + 1);

    // Tìm ConfigType tương ứng
    for (const auto& config : configTypes) {
        if (config->getTypeName() == configTypeStr) {
            if (!config->updateConfig(message)) {
                std::cerr << "Failed to update config for " << configTypeStr << std::endl;
            }
            return; // Đã tìm thấy và xử lý
        }
    }

    std::cerr << "No config handler found for type: " << configTypeStr << std::endl;
}