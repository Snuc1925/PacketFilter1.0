// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define MAX_ENTRIES 1048576  // Maximum number of tracked IPs

// Config state keys
#define CONFIG_KEY_BLACKLIST 0
#define CONFIG_KEY_RATELIMIT 1
#define CONFIG_KEY_WHITELIST 2

// Key structure for LPM Trie map
// ip: IP address of subnet (network byte order)
// prefixlen: Prefix length (e.g., 24 for /24)
struct bpf_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Structure for packet statistics by IP
struct packet_stats {
    __u64 dropped;  // Number of dropped packets
    __u64 passed;   // Number of passed packets
};

// Rate limiting structure - stores configuration for rate-limited IPs
struct ip_rate_limit {
    __u32 packets_per_second; // Maximum packets per second allowed
    __u64 packet_interval_ns; // Minimum interval between packets in nanoseconds
};

// Packet timestamp tracking structure
struct packet_timestamp {
    __u64 last_timestamp; // Last packet timestamp in nanoseconds
};

struct packet_logs {
    __u32 ip;
    __u32 bytes;
    __u32 is_passed;
};

// Blacklist subnet map
// Key: bpf_trie_key (contains subnet and prefixlen)
// Value: Placeholder value (u8), existence of key is enough
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_subnets_map SEC(".maps");

// Whitelist subnet map
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_subnets_map SEC(".maps");

// Config state map
// Key 0: blacklist (0=disabled, 1=enabled)
// Key 1: ratelimit (0=disabled, 1=enabled)
// Key 2: whitelist (0=disabled, 1=enabled)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u8);
} config_state_map SEC(".maps");

// Map for tracking packet statistics per IP address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct packet_stats);
} ip_stats_map SEC(".maps");

// Map for global counters (for quick access to totals)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // 0: dropped, 1: passed
    __type(key, __u32);
    __type(value, __u64);
} global_stats_map SEC(".maps");

// Map for rate limiting configuration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_rate_limit);
} ip_rate_limits_map SEC(".maps");

// Map for tracking packet timestamps (for rate limiting)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct packet_timestamp);
} ip_timestamps_map SEC(".maps");

// Packet ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} packet_ringbuf SEC(".maps");

// Helper function to check if a config is enabled
static __always_inline int is_config_enabled(__u32 config_key) {
    __u8 *state = bpf_map_lookup_elem(&config_state_map, &config_key);
    return state && *state == 1;
}

// Helper function to update statistics and log a dropped packet
static __always_inline void log_drop(struct packet_logs *log, struct packet_stats *ip_stats) {
    if (ip_stats) {
        __sync_fetch_and_add(&ip_stats->dropped, 1);
    }

    __u32 dropped_key = 0;
    __u64 *dropped_count = bpf_map_lookup_elem(&global_stats_map, &dropped_key);
    if (dropped_count) {
        __sync_fetch_and_add(dropped_count, 1);
    }

    log->is_passed = 0;
    bpf_ringbuf_submit(log, 0);
}

// Helper function to update statistics and log a passed packet
static __always_inline void log_pass(struct packet_logs *log, struct packet_stats *ip_stats) {
    if (ip_stats) {
        __sync_fetch_and_add(&ip_stats->passed, 1);
    }

    __u32 passed_key = 1;
    __u64 *passed_count = bpf_map_lookup_elem(&global_stats_map, &passed_key);
    if (passed_count) {
        __sync_fetch_and_add(passed_count, 1);
    }

    log->is_passed = 1;
    bpf_ringbuf_submit(log, 0);
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Get current timestamp
    __u64 current_time = bpf_ktime_get_ns();

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr; // Source IP (network byte order)

    // Allocate ring buffer slot for logging
    struct packet_logs *log = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(*log), 0);
    if (!log) {
        // If we can't allocate, skip logging and pass the packet
        return XDP_PASS;
    }

    // Fill in common log fields
    log->ip = src_ip;
    log->bytes = ctx->data_end - ctx->data;

    // Create key for LPM Trie lookup
    struct bpf_trie_key key = {
        .prefixlen = 32,
        .ip = src_ip
    };

    // Get or initialize packet stats for this IP
    struct packet_stats new_stats = {0};
    struct packet_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!ip_stats) {
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
        ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    }

    // 1. WHITELIST CHECK (if enabled, only allow whitelisted IPs)
    if (is_config_enabled(CONFIG_KEY_WHITELIST)) {
        if (!bpf_map_lookup_elem(&whitelist_subnets_map, &key)) {
            // IP not in whitelist - drop
            bpf_printk("XDP: Dropping packet from non-whitelisted IP: %pI4\n", &src_ip);
            log_drop(log, ip_stats);
            return XDP_DROP;
        }
        // IP is whitelisted, continue to other checks
    }

    // 2. BLACKLIST CHECK (if enabled)
    if (is_config_enabled(CONFIG_KEY_BLACKLIST)) {
        if (bpf_map_lookup_elem(&blacklist_subnets_map, &key)) {
            bpf_printk("XDP: Dropping packet from blacklisted IP/subnet: %pI4\n", &src_ip);
            log_drop(log, ip_stats);
            return XDP_DROP;
        }
    }

    // 3. RATE LIMIT CHECK (if enabled and IP has rate limit configured)
    if (is_config_enabled(CONFIG_KEY_RATELIMIT)) {
        struct ip_rate_limit *rate_limit = bpf_map_lookup_elem(&ip_rate_limits_map, &src_ip);
        if (rate_limit) {
            struct packet_timestamp new_timestamp = {0};
            struct packet_timestamp *timestamp = bpf_map_lookup_elem(&ip_timestamps_map, &src_ip);
            if (!timestamp) {
                new_timestamp.last_timestamp = current_time;
                bpf_map_update_elem(&ip_timestamps_map, &src_ip, &new_timestamp, BPF_ANY);
            } else {
                if (current_time - timestamp->last_timestamp < rate_limit->packet_interval_ns) {
                    bpf_printk("XDP: Rate limit exceeded for IP: %pI4, dropping packet\n", &src_ip);
                    log_drop(log, ip_stats);
                    return XDP_DROP;
                }
                timestamp->last_timestamp = current_time;
            }
        }
    }

    // Packet passed all checks
    log_pass(log, ip_stats);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";