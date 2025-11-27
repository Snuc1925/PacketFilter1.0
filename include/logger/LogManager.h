#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/async.h>

class LogManager {
public:
    static LogManager& instance() {
        static LogManager instance;
        return instance;
    }

    std::shared_ptr<spdlog::logger> getLogger(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_loggers.find(name);
        if (it != m_loggers.end()) {
            return it->second;
        }

        // Create a new async rotating file logger
        auto logger = spdlog::rotating_logger_mt<spdlog::async_factory>(
            name,
            name,
            1024 * 1024 * 10,  // 10MB max size
            3                   // 3 rotated files
        );
        
        m_loggers[name] = logger;
        return logger;
    }

private:
    LogManager() = default;
    ~LogManager() = default;
    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;

    std::unordered_map<std::string, std::shared_ptr<spdlog::logger>> m_loggers;
    std::mutex m_mutex;
};

#endif
