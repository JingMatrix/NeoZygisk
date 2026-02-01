#include "socket_utils.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>

#include "logging.hpp"

namespace socket_utils {

ssize_t xread(int fd, void* buf, size_t count) {
    size_t read_sz = 0;
    ssize_t ret;
    do {
        ret = read(fd, (std::byte*) buf + read_sz, count - read_sz);
        if (ret < 0) {
            if (errno == EINTR) continue;
            PLOGE("read");
            return ret;
        }
        read_sz += ret;
    } while (read_sz != count && ret != 0);
    if (read_sz != count) {
        PLOGE("read (%zu != %zu)", count, read_sz);
    }
    return read_sz;
}

size_t xwrite(int fd, const void* buf, size_t count) {
    size_t write_sz = 0;
    ssize_t ret;
    do {
        ret = write(fd, (std::byte*) buf + write_sz, count - write_sz);
        if (ret < 0) {
            if (errno == EINTR) continue;
            PLOGE("write");
            return write_sz;
        }
        write_sz += ret;
    } while (write_sz != count && ret != 0);
    if (write_sz != count) {
        PLOGE("write (%zu != %zu)", count, write_sz);
    }
    return write_sz;
}

ssize_t xrecvmsg(int sockfd, struct msghdr* msg, int flags) {
    int rec = recvmsg(sockfd, msg, flags);
    if (rec < 0) PLOGE("recvmsg");
    return rec;
}

void* recv_fds(int sockfd, char* cmsgbuf, size_t bufsz, int cnt) {
    // Create a throwaway buffer.
    // It must match the size Rust sends (sizeof(int) = 4 bytes).
    int dummy_data;

    iovec iov = {
        .iov_base = &dummy_data,
        .iov_len = sizeof(dummy_data),
    };
    msghdr msg = {.msg_name = nullptr,
                  .msg_namelen = 0,
                  .msg_iov = &iov,
                  .msg_iovlen = 1,
                  .msg_control = cmsgbuf,
                  .msg_controllen = bufsz,
                  .msg_flags = 0};

    ssize_t rec = xrecvmsg(sockfd, &msg, MSG_WAITALL);

    // --- IO Failed or Stream Desync ---
    if (rec != sizeof(dummy_data)) {
        PLOGE("recv_fds: IO failure. Read %zd bytes, expected %zu", rec, sizeof(dummy_data));
    }

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

    // --- No headers received ---
    if (cmsg == nullptr) {
        LOGE("recv_fds: No control headers received. msg_controllen=%zu",
             (size_t) msg.msg_controllen);
        return nullptr;
    }

    // Check msg_controllen <= bufsz
    if (msg.msg_controllen != bufsz) {
        LOGW("recv_fds: Size mismatch. Buffer capacity: %zu, Received len: %zu", bufsz,
             (size_t) msg.msg_controllen);
    }

    // Check Header Length Field
    size_t expected_cmsg_len = CMSG_LEN(sizeof(int) * cnt);
    if (cmsg->cmsg_len != expected_cmsg_len) {
        LOGW("recv_fds: CMSG header len mismatch. Header says: %zu, Calculated: %zu (cnt=%d)",
             (size_t) cmsg->cmsg_len, expected_cmsg_len, cnt);
    }

    // Check Protocol details
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        LOGW("recv_fds: Protocol mismatch. Level: %d (exp %d), Type: %d (exp %d)", cmsg->cmsg_level,
             SOL_SOCKET, cmsg->cmsg_type, SCM_RIGHTS);
    }

    // Return data anyway so we can see if the FD is valid
    return CMSG_DATA(cmsg);
}

template <typename T>
inline T read_exact_or(int fd, T fail) {
    T res;
    return sizeof(T) == xread(fd, &res, sizeof(T)) ? res : fail;
}

template <typename T>
inline bool write_exact(int fd, T val) {
    return sizeof(T) == xwrite(fd, &val, sizeof(T));
}

uint8_t read_u8(int fd) { return read_exact_or<uint8_t>(fd, 0); }

uint32_t read_u32(int fd) { return read_exact_or<uint32_t>(fd, 0); }

size_t read_usize(int fd) { return read_exact_or<size_t>(fd, 0); }

bool write_usize(int fd, size_t val) { return write_exact<size_t>(fd, val); }

std::string read_string(int fd) {
    auto len = read_usize(fd);
    char* buf = new char[len + 1];
    buf[len] = '\0';
    xread(fd, buf, len);
    return buf;
}

bool write_u8(int fd, uint8_t val) { return write_exact<uint8_t>(fd, val); }

bool write_u32(int fd, uint32_t val) { return write_exact<uint32_t>(fd, val); }

bool write_string(int fd, std::string_view str) {
    return write_usize(fd, str.size()) && str.size() == xwrite(fd, str.data(), str.size());
}

int recv_fd(int sockfd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    void* data = recv_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), 1);
    if (data == nullptr) return -1;

    int result;
    memcpy(&result, data, sizeof(int));
    return result;
}
}  // namespace socket_utils
