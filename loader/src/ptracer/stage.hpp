#pragma once

#include <string_view>

/// The boot stages, as the managers know them. Each one used to be a shell script of its
/// own, re-deriving the situation from environment variables; they are now shims that
/// forward to `stage <name>`.
enum class Stage {
    PostFsData,
    PostMount,
    Service,
    HotInstall,
    LateLoad,
};

struct StageOptions {
    /// Load modules that are marked disabled, and run their boot scripts.
    bool ignore_disable = false;
    /// Set SELinux permissive when the loaded policy is missing our rules.
    bool permissive = false;
    /// Undo an arm instead of performing it.
    bool stop = false;
};

/// Looks up a stage by the name a shim passes. Returns false for an unknown name.
bool parse_stage(std::string_view name, Stage &out);

int run_stage(Stage stage, const StageOptions &options);

/// Prints what the monitor and the daemon report, for the manager's action button.
int print_status();
