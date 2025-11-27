#include <iostream>
#include "logger/AccessLogWriter.h"
#include "logger/LogManager.h"
#include "MapFdManager.h"

int AccessLogWriter::handle_log_event(void *ctx, void *data, size_t size) {
    auto* buf = static_cast<BufferContext*>(ctx);
    auto* log = static_cast<const struct packet_logs*>(data);

    auto now = std::chrono::system_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());

    buf->buffer.push_back({
        ns,
        log->ip,
        log->bytes,
        log->is_passed
    });

    bool full = buf->buffer.size() >= buf->buffer_size;
    bool timeout = (std::chrono::steady_clock::now() - buf->lastWrite) > buf->timeout;

    if (full || timeout) {
        buf->flush();
    }

    return 0;
}

void AccessLogWriter::startLogListener() {
    map_fd_packet_ringbuf = MapFdManager::getInstance().get_map_fd_by_name("packet_ringbuf");

    if (map_fd_packet_ringbuf < 0) {
        std::cerr << "Cannot open packet ringbuf map\n";
        return;
    }

    worker = std::thread(&AccessLogWriter::process, this);
}

void AccessLogWriter::process() {
    auto logger = LogManager::instance().getLogger(logPath);
    BufferContext ctx(Constants::DEFAULT_LOG_ACCESS_BUFFER_SIZE, Constants::DEFAULT_LOG_ACCESS_TIMEOUT_MS, logger);

    struct ring_buffer* rb = ring_buffer__new(
        map_fd_packet_ringbuf,
        handle_log_event,
        &ctx,
        nullptr
    );

    if (!rb) {
        logger->error("Could not create ring buffer");
        return;
    }

    while (!exiting.load()) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            logger->error("ring_buffer poll error {}", strerror(-err));
            break;
        }

        if ((std::chrono::steady_clock::now() - ctx.lastWrite) > ctx.timeout
            && !ctx.buffer.empty()) {
            ctx.flush();
        }
    }

    ctx.flush();
    ring_buffer__free(rb);
}

void AccessLogWriter::log(std::shared_ptr<spdlog::logger> logger) {
    // Không dùng – vì AccessLogWriter log qua ring buffer
}
