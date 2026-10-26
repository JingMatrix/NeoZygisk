#include "misc.hpp"

#include <sys/utsname.h>

#include <charconv>
#include <cstdio>
#include <string_view>

#include "logging.hpp"

/**
 * @brief Parses an integer from a string_view.
 *
 * This function uses std::from_chars for safe, high-performance conversion.
 * It adheres to the original signature, returning an integer value.
 *
 * @param s The string_view to parse.
 * @return The parsed integer on success. Returns -1 on failure (e.g., invalid
 * format, overflow, or non-numeric characters). Note the ambiguity: a
 * successful parse of "-1" cannot be distinguished from a failure.
 */
int parse_int(std::string_view s) {
    int value{};

    // std::from_chars attempts to parse an integer from the provided character range.
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);

    // A successful parse must have no error code and consume the entire string.
    if (ec == std::errc() && ptr == s.data() + s.size()) {
        return value;
    }

    // Return the designated error value if parsing fails.
    return -1;
}

bool kernel_keeps_ptrace_message() {
    static const bool keeps = [] {
        utsname uts{};
        if (uname(&uts) == -1) {
            PLOGE("uname");
            return false;
        }
        int major = 0, minor = 0;
        if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
            LOGW("cannot read a version out of kernel release %s", uts.release);
            return false;
        }
        bool before_5_3 = major < 5 || (major == 5 && minor < 3);
        LOGV("kernel %s %s the ptrace event message", uts.release, before_5_3 ? "keeps" : "clears");
        return before_5_3;
    }();
    return keeps;
}
