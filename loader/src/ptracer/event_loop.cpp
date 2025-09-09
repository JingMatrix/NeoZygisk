#include "event_loop.hpp"

#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "logging.hpp"

EventLoop::EventLoop() : epoll_fd_(-1), running(false) {}

EventLoop::~EventLoop() {
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
}

bool EventLoop::Init() {
    epoll_fd_ = epoll_create(1);
    if (epoll_fd_ == -1) {
        PLOGE("create epoll fd");
        return false;
    }
    return true;
}

void EventLoop::Stop() { running = false; }

void EventLoop::Loop() {
    running = true;
    constexpr auto MAX_EVENTS = 2;
    struct epoll_event events[MAX_EVENTS];

    while (running) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno != EINTR) {
                PLOGE("epoll_wait");
            }
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            // Dispatch the event to the handler stored in the data pointer.
            reinterpret_cast<EventHandler *>(events[i].data.ptr)
                ->HandleEvent(*this, events[i].events);
            if (!running) break;
        }
    }
}

bool EventLoop::RegisterHandler(EventHandler &handler, uint32_t events) {
    struct epoll_event ev{};
    ev.events = events;
    ev.data.ptr = &handler;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, handler.GetFd(), &ev) == -1) {
        PLOGE("add event handler");
        return false;
    }
    return true;
}
