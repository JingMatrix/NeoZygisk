## 🚀 v2.2 - Bug Fixes and Enhanced Compatibility 🚀

This release squashes several bugs introduced in the v2.0 refactoring and streamlines performance.

### 🐛 Bug Fixes

*   **LSPosed Compatibility**: The `Zygisk` daemon now correctly cleans up all traces of LSPosed mounts. This regression was addressed in the hot-fix release v2.1.
*   **Corrected Mount Logic**: Overhauled the logic for determining an application's mount namespace. This fixes a critical bug where system apps installed as modules (e.g., Basic Call Recorder) would fail to launch.

### 💥 Breaking Change

*   **Dropping 32-bit Support on 64-bit Devices** 🚮: To simplify the code and improve stability, NeoZygisk will no longer inject into 32-bit-only applications running on 64-bit devices. This change helps resolve compatibility issues on Android 10 and reflects the rarity of modern 32-bit-only apps.
