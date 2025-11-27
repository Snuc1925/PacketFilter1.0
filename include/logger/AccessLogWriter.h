#ifndef ACCESS_LOG_WRITER_H
#define ACCESS_LOG_WRITER_H

#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include <chrono>
#include <spdlog/spdlog.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "Constants.h"

// Matches packet_logs in packetfilter.bpf.c
struct packet_logs {
    uint32_t ip;
    uint32_t bytes;
    uint32_t is_passed;
};

// Structure for buffered log entries
struct LogEntry {
    std::chrono::nanoseconds timestamp;
    uint32_t ip;
    uint32_t bytes;
    uint32_t is_passed;
};

// Buffer context for ring buffer callback
struct BufferContext {
    std::vector<LogEntry> buffer;
    size_t buffer_size;
    std::chrono::milliseconds timeout;
    std::chrono::steady_clock::time_point lastWrite;
    std::shared_ptr<spdlog::logger> logger;

    BufferContext(size_t size, int timeout_ms, std::shared_ptr<spdlog::logger> log)
        : buffer_size(size)
        , timeout(timeout_ms)
        , lastWrite(std::chrono::steady_clock::now())
        , logger(log) {
        buffer.reserve(size);
    }

    void flush() {
        if (buffer.empty()) return;
        
        for (const auto& entry : buffer) {
            struct in_addr addr;
            addr.s_addr = entry.ip;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            
            logger->info("{} {} {} {}", 
                entry.timestamp.count(),
                ip_str,
                entry.bytes,
                entry.is_passed ? "PASS" : "DROP");
        }
        
        buffer.clear();
        lastWrite = std::chrono::steady_clock::now();
    }
};

// Base class for log writers - allows extensibility for different log types
class LogWriter {
public:
    virtual ~LogWriter() = default;
    virtual void startLogListener() = 0;
    virtual void stopLogListener() = 0;
    virtual void log(std::shared_ptr<spdlog::logger> logger) = 0;
};

class AccessLogWriter : public LogWriter {
public:
    AccessLogWriter() = default;
    ~AccessLogWriter() override {
        stopLogListener();
    }

    void startLogListener() override;
    void stopLogListener() override {
        exiting.store(true);
        if (worker.joinable()) {
            worker.join();
        }
    }
    void log(std::shared_ptr<spdlog::logger> logger) override;

private:
    static int handle_log_event(void *ctx, void *data, size_t size);
    void process();

    std::atomic<bool> exiting{false};
    std::thread worker;
    int map_fd_packet_ringbuf = -1;
    std::string logPath = Constants::DEFAULT_LOG_ACCESS();
};

#endif
