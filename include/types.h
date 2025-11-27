#ifndef TYPES_H
#define TYPES_H

#include <cstdint>

// IPSubnet structure used for LPM trie map keys
// This matches the bpf_trie_key structure in packetfilter.bpf.c
struct IPSubnet {
    uint32_t prefixlen;
    uint32_t ip;
};

// Rate limit structure - matches ip_rate_limit in packetfilter.bpf.c
struct IPRateLimitConfig {
    uint32_t packets_per_second;
    uint64_t packet_interval_ns;
};

// Config state map keys - must match definitions in packetfilter.bpf.c
namespace ConfigKey {
    constexpr uint32_t BLACKLIST = 0;
    constexpr uint32_t RATELIMIT = 1;
    constexpr uint32_t WHITELIST = 2;
}

#endif
