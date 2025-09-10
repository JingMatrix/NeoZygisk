## 🚀 **v2.0 - Advanced Stealth & Clarity** 🚀

This is a complete rewrite, focused on elegant evasion techniques and a more maintainable, clear architecture!

#### 🥷 **Advanced Evasion Techniques**

*   🛡️ **`atexit` Detection Neutralized**: Actively resets the global `atexit` handler array, erasing all module fingerprints.
*   🧹 **Zygote Stack Cleaning**: Wipes root mount fossils from the Zygote stack to restore a pristine, non-root state.
*   👻 **Direct Unmounting**: Aggressively unmounts traces from within Zygote before applications can inspect them.
*   🧼 **Efficient Linker Cleaning**: Elegantly removes all library traces from memory using the `soinfo_unload` function.
*   🧠 **Smarter Namespace Logic**: Refines mount logic to hide traces without creating new, detectable side-effects.

---

💡 **For Module Developers:**

You no longer need to handle `atexit` evasion. NeoZygisk now completely neutralizes this detection vector for all loaded modules automatically! ✨

#### 🔧 **Core Overhaul & Clarity**

*   🏗️ **Total Rewrite**: Re-engineered the `Zygisk` daemon and `ptrace` monitor for maximum stability and clarity.
*   ✨ **Modernized Internals**: Updated all core utilities for better performance, readability, and documentation.
