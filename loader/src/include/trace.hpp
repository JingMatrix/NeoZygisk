#pragma once

enum TraceMode {
    UNKNOWN = 0,
    SPAWN = 1,
    STANDALONE = 2,
    SYSTEM_SERVER = 3,
};

/// The name a mode is logged under, which is also the flag `trace` takes for it.
inline const char *name_of(TraceMode mode) {
    switch (mode) {
    case TraceMode::SPAWN:
        return "spawn";
    case TraceMode::STANDALONE:
        return "standalone";
    case TraceMode::SYSTEM_SERVER:
        return "system_server";
    default:
        return "unknown";
    }
}
