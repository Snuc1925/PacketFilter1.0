// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define MAX_ENTRIES 1048576  // Maximum number of tracked IPs

// Cấu trúc key cho LPM Trie map
// ip: Địa chỉ IP của subnet (network byte order)
// prefixlen: Độ dài tiền tố (ví dụ: 24 cho /24)
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

// Định blacklist subnet
// Key: bpf_trie_key (chứa subnet và prefixlen)
// Value: Một giá trị placeholder (u8), sự tồn tại của key đã đủ
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES); // Số lượng subnet tối đa
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC); // Không cấp phát trước, tiết kiệm bộ nhớ
} blacklist_subnets_map SEC(".maps"); // Đổi tên map để rõ ràng hơn

// Config state map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u8);
} config_state_map SEC(".maps");
// 0: blacklist
// 1: ratelimit
// 2: whitelist

// Map for tracking packet statistics per IP address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES); // Maximum number of tracked IPs
    __type(key, __u32);               // IP address as key
    __type(value, struct packet_stats); // Statistics as value
} ip_stats_map SEC(".maps");

// Map for global counters (for quick access to totals)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // 0: dropped, 1: passed
    __type(key, __u32);
    __type(value, __u64);
} global_stats_map SEC(".maps");

// New map for rate limiting configuration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);  // Maximum number of rate-limited IPs
    __type(key, __u32);                // IP address as key
    __type(value, struct ip_rate_limit); // Rate limit configuration as value
} ip_rate_limits_map SEC(".maps");

// New map for tracking packet timestamps (for rate limiting)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);  // Maximum number of tracked IPs
    __type(key, __u32);                // IP address as key
    __type(value, struct packet_timestamp); // Timestamp tracking as value
} ip_timestamps_map SEC(".maps");

// Packet ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} packet_ringbuf SEC(".maps");

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

    __u32 src_ip = ip->saddr; // IP nguồn của gói tin (network byte order)

    // <<< THAY ĐỔI BẮT ĐẦU >>>
    // 1. Cấp phát slot trong ring buffer trước
    struct packet_logs *log = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(*log), 0);
    if (!log) {
        // Nếu không thể cấp phát, chúng ta bỏ qua việc ghi log và cho gói tin đi qua
        return XDP_PASS;
    }

    // 2. Điền các thông tin chung vào log
    log->ip = src_ip;
    log->bytes = ctx->data_end - ctx->data;
    // <<< THAY ĐỔI KẾT THÚC >>>

    // Tạo key để tra cứu trong LPM Trie
    struct bpf_trie_key key = {
        .prefixlen = 32, // Khi tìm một IP cụ thể trong subnet map, dùng prefixlen 32
        .ip = src_ip
    };

    // Get or initialize packet stats for this IP
    struct packet_stats new_stats = {0};
    struct packet_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!ip_stats) {
        // If this IP isn't in the map yet, initialize it with zeros
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
        ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
        if (!ip_stats) {
            goto process_packet;
        }
    }

    // Rate limiting check - only if this IP has a rate limit configured
    struct ip_rate_limit *rate_limit = bpf_map_lookup_elem(&ip_rate_limits_map, &src_ip);
    if (rate_limit) {
        // Lookup or initialize timestamp tracking for this IP
        struct packet_timestamp new_timestamp = {0};
        struct packet_timestamp *timestamp = bpf_map_lookup_elem(&ip_timestamps_map, &src_ip);
        if (!timestamp) {
            new_timestamp.last_timestamp = current_time;
            bpf_map_update_elem(&ip_timestamps_map, &src_ip, &new_timestamp, BPF_ANY);
        } else {
            // Check if packet arrived too soon
            if (current_time - timestamp->last_timestamp < rate_limit->packet_interval_ns) {
                // Packet arrived too soon - rate limit exceeded
                bpf_printk("XDP: Rate limit exceeded for IP: %pI4, dropping packet\n", &src_ip);

                if (ip_stats) {
                    __sync_fetch_and_add(&ip_stats->dropped, 1);
                }

                __u32 dropped_key = 0;
                __u64 *dropped_count = bpf_map_lookup_elem(&global_stats_map, &dropped_key);
                if (dropped_count) {
                    __sync_fetch_and_add(dropped_count, 1);
                }

                // <<< THAY ĐỔI BẮT ĐẦU >>>
                // 3. Ghi log gói tin bị DROP và gửi đi
                log->is_passed = 0; // 0 = drop
                bpf_ringbuf_submit(log, 0);
                // <<< THAY ĐỔI KẾT THÚC >>>

                return XDP_DROP;
            }
            timestamp->last_timestamp = current_time;
        }
    }

process_packet:
    // Kiểm tra xem IP nguồn có nằm trong bất kỳ subnet bị blacklist nào không
    if (bpf_map_lookup_elem(&blacklist_subnets_map, &key)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP/subnet: %pI4\n", &src_ip);

        if (ip_stats) {
            __sync_fetch_and_add(&ip_stats->dropped, 1);
        }

        __u32 dropped_key = 0;
        __u64 *dropped_count = bpf_map_lookup_elem(&global_stats_map, &dropped_key);
        if (dropped_count) {
            __sync_fetch_and_add(dropped_count, 1);
        }

        // <<< THAY ĐỔI BẮT ĐẦU >>>
        // 4. Ghi log gói tin bị DROP và gửi đi
        log->is_passed = 0; // 0 = drop
        bpf_ringbuf_submit(log, 0);
        // <<< THAY ĐỔI KẾT THÚC >>>

        return XDP_DROP; // Chặn gói tin
    }

    // Update IP-specific passed statistics
    if (ip_stats) {
        __sync_fetch_and_add(&ip_stats->passed, 1);
    }

    // Update global passed counter
    __u32 passed_key = 1;
    __u64 *passed_count = bpf_map_lookup_elem(&global_stats_map, &passed_key);
    if (passed_count) {
        __sync_fetch_and_add(passed_count, 1);
    }

    // <<< THAY ĐỔI BẮT ĐẦU >>>
    // 5. Ghi log gói tin được PASS và gửi đi
    log->is_passed = 1; // 1 = passed
    bpf_ringbuf_submit(log, 0);
    // <<< THAY ĐỔI KẾT THÚC >>>

    return XDP_PASS; // Cho qua
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";