#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <memory>
#include <vector>
#include <functional>
#include "MapFdManager.h"
#include "ConfigType.h"
#include "config/FileEventSource.h"

class ConfigManager {
public:
    ~ConfigManager(); 
    std::string getInterface();
    bool loadAllConfigs();
    void startEventListener();
    void stopEventListener();

private:
    void processEventMessage(const std::string& line);
    
    std::vector<std::unique_ptr<ConfigType>> configTypes;
    std::unique_ptr<EventSource> m_eventSource;
};

#endif