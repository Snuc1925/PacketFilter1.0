#include "config/ConfigManager.h"
#include "Constants.h"
#include "config/ConfigType.h"
#include "config/type/Blacklist.h"
#include "config/type/Whitelist.h"
#include "config/type/RateLimit.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

// This is the only place that knows about FileEventSource
#include "config/FileEventSource.h"

ConfigManager::~ConfigManager() {
    stopEventListener();
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
    // Load Blacklist config
    auto blacklist = std::make_unique<Blacklist>();
    if (!blacklist->loadConfig()) {
        std::cerr << "Warning: Blacklist config load unsuccessful" << std::endl;
        // Continue loading other configs
    }
    configTypes.push_back(std::move(blacklist));

    // Load Whitelist config
    auto whitelist = std::make_unique<Whitelist>();
    if (!whitelist->loadConfig()) {
        std::cerr << "Warning: Whitelist config load unsuccessful" << std::endl;
        // Continue loading other configs
    }
    configTypes.push_back(std::move(whitelist));

    // Load RateLimit config
    auto ratelimit = std::make_unique<RateLimit>();
    if (!ratelimit->loadConfig()) {
        std::cerr << "Warning: RateLimit config load unsuccessful" << std::endl;
        // Continue loading other configs
    }
    configTypes.push_back(std::move(ratelimit));

    std::cout << "Load configs successfully...\n";
    return true;
}

void ConfigManager::startEventListener() {
    if (m_eventSource) {
        std::cout << "Event listener already running." << std::endl;
        return;
    }
    
    // Create the event source (can be swapped for ConsulEventSource, etc.)
    m_eventSource = std::make_unique<FileEventSource>(
        Constants::DEFAULT_CONFIG_EVENT_LISTENER()
    );

    // Set callback with exception handling for thread safety
    m_eventSource->setCallback(
        [this](const std::string& msg) {
            try {
                this->processEventMessage(msg);
            } catch (const std::exception& e) {
                std::cerr << "Exception in processEventMessage: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "Unknown exception in processEventMessage" << std::endl;
            }
        }
    );
    
    // Start and check for errors
    if (!m_eventSource->start()) {
        std::cerr << "CRITICAL WARNING: Config event listener failed to start. "
                  << "Dynamic config updates will be DISABLED." << std::endl;
        m_eventSource.reset(); 
        // Main thread continues running
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
 * @brief Process event message (runs on EventSource thread)
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

    // Trim whitespace
    configTypeStr.erase(0, configTypeStr.find_first_not_of(" \t\n\r"));
    configTypeStr.erase(configTypeStr.find_last_not_of(" \t\n\r") + 1);
    message.erase(0, message.find_first_not_of(" \t\n\r"));
    message.erase(message.find_last_not_of(" \t\n\r") + 1);

    // Find matching ConfigType
    for (const auto& config : configTypes) {
        if (config->getTypeName() == configTypeStr) {
            if (!config->updateConfig(message)) {
                std::cerr << "Failed to update config for " << configTypeStr << std::endl;
            }
            return;
        }
    }

    std::cerr << "No config handler found for type: " << configTypeStr << std::endl;
}