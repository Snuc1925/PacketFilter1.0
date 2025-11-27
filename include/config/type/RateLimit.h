#ifndef RATELIMIT_H
#define RATELIMIT_H 

#include "config/ConfigType.h"
#include <cstdint>

class RateLimit : public ConfigType {
public:
    ~RateLimit();
    bool loadConfig() override;
    bool updateConfig(const std::string& message) override;
    std::string getTypeName() const override { return "ratelimit"; }

private:
    int map_fd_rate_limits = -1;
    int map_fd_config_state = -1;

    bool add_rate_limit(uint32_t ip, uint32_t packets_per_second);
    bool remove_rate_limit(uint32_t ip);
    bool disable_ratelimit();
    bool enable_ratelimit();
};

#endif
