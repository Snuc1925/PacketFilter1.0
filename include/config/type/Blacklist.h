#ifndef BLACKLIST_H
#define BLACKLIST_H 

#include "config/ConfigType.h"

// Forward declaration to avoid including types.h in header
struct IPSubnet;

class Blacklist : public ConfigType {
public:
    ~Blacklist();
    bool loadConfig() override;
    bool updateConfig(const std::string& message) override;
    std::string getTypeName() const override { return "blacklist"; }

private:
    int map_fd_blacklist_subnets = -1;
    int map_fd_config_state = -1;

    bool add_ip_subnets(IPSubnet* key);
    bool remove_ip_subnets(IPSubnet* key);
    bool disable_blacklist();
    bool enable_blacklist();
};

#endif