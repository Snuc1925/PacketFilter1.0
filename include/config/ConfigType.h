#ifndef CONFIG_TYPE_H
#define CONFIG_TYPE_H 

#include <string>

class ConfigType {
public:
    virtual ~ConfigType() = default;
    virtual bool loadConfig() = 0;
    virtual bool updateConfig(const std::string& message) = 0;
    virtual std::string getTypeName() const = 0;
};

#endif 