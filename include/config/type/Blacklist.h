#ifndef BLACKLIST_H
#define BLACKLIST_H 

#include "config/ConfigType.h"

class Blacklist : public ConfigType {
public:
    ~Blacklist();
    bool loadConfig() override;
    bool updateConfig(const std::string& message) override;
private:
    int map_fd_blacklist_subnets = -1;
    int map_fd_config_state = -1;

    bool add_ip_subnets();
    bool remove_ip_subnets();
    bool disable_blacklist();
    bool enable_blacklist();
};

#endif