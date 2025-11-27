#ifndef FILE_EVENT_SOURCE_H
#define FILE_EVENT_SOURCE_H

#include <string>
#include <functional>
#include <thread>
#include <atomic>

// Base class for event sources - allows extensibility for different sources
// (e.g., FileEventSource, ConsulEventSource, etc.)
class EventSource {
public:
    virtual ~EventSource() = default;
    virtual void setCallback(std::function<void(const std::string&)> callback) = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;
};

class FileEventSource : public EventSource {
public:
    explicit FileEventSource(const std::string& filePath);
    ~FileEventSource() override;

    void setCallback(std::function<void(const std::string&)> callback) override;
    bool start() override;
    void stop() override;

private:
    void run();

    std::string m_filePath;
    std::atomic<bool> m_isRunning;
    std::thread m_listenerThread;
    std::function<void(const std::string&)> m_callback;
    
    int m_inotifyFd = -1;
    int m_watchFd = -1;
    int m_eventFd = -1;
};

#endif
