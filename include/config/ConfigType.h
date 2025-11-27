#ifndef CONFIG_TYPE_H
#define CONFIG_TYPE_H 

#include <string>

class ConfigType {
public:
    virtual ~ConfigType() = default;
    virtual bool loadConfig() = 0;
    virtual bool updateConfig(const std::string& message) = 0;

    // void registerMapFdManager(std::shared_ptr<MapFdManager> mgr) {
    //     mapFdManager = std::move(mgr);
    // }

protected:
    // std::shared_ptr<MapFdManager> mapFdManager;
};

#endif 