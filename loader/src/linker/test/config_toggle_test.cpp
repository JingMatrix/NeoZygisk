// Exercises the real is_custom_linker_enabled() / is_anonymous_memory_enabled()
// (clean.cpp) against an actual config.prop at the hardcoded path they read
// (kConfigPath = /data/adb/nyazygisk/config.prop) — safe to create for real
// inside this chroot. Links clean.cpp directly, same as spoof_rwx_test.cpp.
#include <stdio.h>
#include <sys/stat.h>

#include "zygisk.hpp"

namespace {
int g_failures = 0;
void Check(const char* what, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_failures++;
}

constexpr const char* kConfigDir = "/data/adb/nyazygisk";
constexpr const char* kConfigPath = "/data/adb/nyazygisk/config.prop";

void WriteConfig(const char* contents) {
    remove(kConfigPath);
    if (contents == nullptr) return;  // missing file case
    FILE* f = fopen(kConfigPath, "w");
    if (f == nullptr) {
        printf("fopen(%s) for writing failed\n", kConfigPath);
        return;
    }
    fputs(contents, f);
    fclose(f);
}
}  // namespace

int main() {
    mkdir("/data/adb", 0755);  // mkdir doesn't create parents; the rootfs may lack this
    mkdir(kConfigDir, 0755);

    printf("== custom_linker: opt-in semantics\n");
    WriteConfig(nullptr);  // no config.prop at all (fresh install)
    Check("missing config.prop -> custom linker stays off", !is_custom_linker_enabled());

    WriteConfig("anonymous_memory=1\n");  // present, but no custom_linker line
    Check("config.prop without the key -> custom linker stays off", !is_custom_linker_enabled());

    WriteConfig("custom_linker=0\n");
    Check("custom_linker=0 -> disabled", !is_custom_linker_enabled());

    WriteConfig("custom_linker=1\n");
    Check("custom_linker=1 -> enabled", is_custom_linker_enabled());

    WriteConfig("anonymous_memory=1\ncustom_linker=1\nexclude_unmount=1\n");
    Check("custom_linker=1 among other keys -> still enabled", is_custom_linker_enabled());

    printf("== anonymous_memory: opt-in semantics (regression check on the shared helper)\n");
    WriteConfig(nullptr);
    Check("missing config.prop -> anonymous memory stays off", !is_anonymous_memory_enabled());
    WriteConfig("custom_linker=0\n");
    Check("config.prop without the key -> anonymous memory stays off",
          !is_anonymous_memory_enabled());
    WriteConfig("anonymous_memory=1\n");
    Check("anonymous_memory=1 -> enabled", is_anonymous_memory_enabled());

    printf("== plt_engine: bytehook default vs lsplt opt-in\n");
    WriteConfig(nullptr);
    Check("missing config.prop -> lsplt is off (bytehook default)", !is_lsplt_engine_configured());
    WriteConfig("plt_engine=bytehook\n");
    Check("plt_engine=bytehook -> lsplt is off", !is_lsplt_engine_configured());
    WriteConfig("plt_engine=lsplt\n");
    Check("plt_engine=lsplt -> lsplt is on", is_lsplt_engine_configured());
    WriteConfig("anonymous_memory=1\nplt_engine=lsplt\ncustom_linker=1\n");
    Check("plt_engine=lsplt among other keys -> lsplt is on", is_lsplt_engine_configured());

    remove(kConfigPath);
    printf("\n%s (%d failure(s))\n", g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures);
    return g_failures == 0 ? 0 : 1;
}
