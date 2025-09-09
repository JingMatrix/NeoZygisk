#pragma once

#include <cstdint>

// Forward declaration
class EventLoop;

/**
 * @brief An abstract interface for event handlers.
 *
 * Any class that wants to be managed by the EventLoop must implement this
 * interface. It provides a contract for getting a file descriptor to watch
 * and a method to handle events on that descriptor.
 */
struct EventHandler {
    virtual int GetFd() = 0;
    virtual void HandleEvent(EventLoop &loop, uint32_t event) = 0;
    virtual ~EventHandler() = default;
};

/**
 * @brief A generic, epoll-based event loop.
 *
 * This class provides a simple abstraction over Linux's epoll mechanism.
 * It allows for registering multiple EventHandlers, each associated with a
 * file descriptor, and runs a loop that dispatches events to the appropriate
 * handler.
 */
class EventLoop {
public:
    EventLoop();
    ~EventLoop();

    // Disable copy and move
    EventLoop(const EventLoop &) = delete;
    EventLoop &operator=(const EventLoop &) = delete;

    bool Init();
    void Stop();
    void Loop();
    bool RegisterHandler(EventHandler &handler, uint32_t events);

private:
    int epoll_fd_;
    bool running;
};
