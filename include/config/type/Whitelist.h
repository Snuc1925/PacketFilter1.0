#ifndef WHITELIST_H
#define WHITELIST_H 

#include "config/ConfigType.h"

// Forward declaration
struct IPSubnet;

class Whitelist : public ConfigType {
public:
    ~Whitelist();
    bool loadConfig() override;
    bool updateConfig(const std::string& message) override;
    std::string getTypeName() const override { return "whitelist"; }

private:
    int map_fd_whitelist_subnets = -1;
    int map_fd_config_state = -1;

    bool add_ip_subnets(IPSubnet* key);
    bool remove_ip_subnets(IPSubnet* key);
    bool disable_whitelist();
    bool enable_whitelist();
};

#endif
