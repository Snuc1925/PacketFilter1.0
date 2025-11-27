#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <memory>
#include <vector>
#include "MapFdManager.h"
#include "ConfigType.h"  
// #include "ConfigEventListener.h"

class ConfigManager {
public:
    ~ConfigManager(); 
    std::string getInterface();
    bool loadAllConfigs();
    // void addConfig(std::unique_ptr<ConfigType> config);
    // void registerConfigListener(std::unique_ptr<ConfigEventListener> configListener);
private:
    std::vector<std::unique_ptr<ConfigType>> configTypes;
    // std::unique_ptr<ConfigEventListener> configEventListener;    
};

#endif