const PROP_PATH = "/data/adb/nyazygisk/module.prop";
const CONFIG_PATH = "/data/adb/nyazygisk/config.prop";
const CONFIG_DIR = "/data/adb/nyazygisk";
const PACKAGES_LIST_PATH = "/data/system/packages.list";
const MODULE_MARKER = "@@NZMOD@@ ";
const LANG_STORAGE_KEY = "nyazygisk.lang";
const GOOD_STATUSES = new Set(["running", "injected", "tracing"]);
const BAD_STATUSES = new Set(["stopped", "exited", "crashed", "not_injected"]);
const PACKAGE_RE = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/;

const I18N = {
  en: {
    language: "Language",
    tabs: "Tabs",
    tab_overview: "Overview",
    info: "Device & environment",
    modules: "Active modules",
    settings: "Settings",
    monitor: "Zygote monitor",
    zygote: "Zygote",
    daemon: "Daemon",
    root: "Root",
    rom: "System",
    kernel: "Kernel",
    sdk: "Android SDK",
    abi: "ABI",
    running: "Running",
    tracing: "Tracing",
    stopped: "Stopped",
    exited: "Exited",
    injected: "Injected",
    not_injected: "Not injected",
    crashed: "Crashed",
    unknown: "Unknown",
    status_ok: "All systems working",
    status_ok_hint: "Every component is injected and running",
    status_warn: "Partially working",
    status_warn_hint: "Some components are not running; modules may not load",
    status_down: "Not working",
    status_down_hint: "Zygisk is not active. Try rebooting the device",
    status_unknown: "Status unknown",
    status_unknown_hint: "The current status could not be read",
    reload: "Reload",
    modules_none: "No active Zygisk modules",
    target: "Target",
    by_author: "by",
    reloaded: "Reloaded",
    saved: "Saved",
    load_failed: "Failed to read module status",
    save_failed: "Failed to save setting",
    bridge_missing: "No supported WebUI bridge detected",
    anonymous_memory: "Anonymous memory",
    anonymous_memory_hint: "Hide module mappings after specialization",
    custom_linker: "Custom linker",
    custom_linker_hint: "Load modules without the system linker (experimental)",
    plt_engine: "PLT hook engine",
    plt_engine_hint: "Hook implementation for ZN modules",
    app_exclude: "App exclusion",
    app_exclude_hint: "Checked user apps load no Zygisk modules. System apps cannot be excluded. Changes take effect the next time the app starts.",
    exclude_unmount: "Unmount for excluded apps",
    exclude_unmount_hint: "Also hide module mounts, like the DenyList",
    search_apps: "Search name or package",
    user_apps: "User apps",
    filter_all: "All",
    filter_excluded: "Excluded",
    apps_loading: "Loading apps…",
    apps_failed: "Failed to list apps",
    apps_none: "No user apps",
    apps_no_match: "No matching apps",
    pending_restart: "Restart app",
    shared_uid: "Shares a UID with {n} other package(s); they switch together",
    shared_uid_system: "Shares a UID with a system package and cannot be excluded",
  },
  "zh-Hant": {
    language: "語言",
    tabs: "分頁",
    tab_overview: "總覽",
    info: "裝置與環境",
    modules: "已啟用模組",
    settings: "設定",
    monitor: "Zygote 監控",
    zygote: "Zygote",
    daemon: "守護程序",
    root: "Root 方案",
    rom: "系統",
    kernel: "核心",
    sdk: "Android SDK",
    abi: "ABI",
    running: "執行中",
    tracing: "追蹤中",
    stopped: "已停止",
    exited: "已退出",
    injected: "已注入",
    not_injected: "未注入",
    crashed: "已崩潰",
    unknown: "未知",
    status_ok: "運作正常",
    status_ok_hint: "所有元件已注入並在執行",
    status_warn: "部分異常",
    status_warn_hint: "有元件未在執行，模組可能無法載入",
    status_down: "未運作",
    status_down_hint: "Zygisk 未啟用，請嘗試重新開機",
    status_unknown: "狀態未知",
    status_unknown_hint: "無法讀取目前狀態",
    reload: "重新整理",
    modules_none: "沒有已啟用的 Zygisk 模組",
    target: "目標",
    by_author: "作者",
    reloaded: "已重新整理",
    saved: "已儲存",
    load_failed: "讀取模組狀態失敗",
    save_failed: "儲存設定失敗",
    bridge_missing: "找不到支援的 WebUI bridge",
    anonymous_memory: "匿名記憶體",
    anonymous_memory_hint: "特化後隱藏模組的記憶體映射",
    custom_linker: "自訂鏈接器",
    custom_linker_hint: "不經過系統鏈接器載入模組（實驗性）",
    plt_engine: "PLT Hook 引擎",
    plt_engine_hint: "ZN 模組的 PLT Hook 實現",
    app_exclude: "應用排除",
    app_exclude_hint: "勾選的使用者應用不載入任何 Zygisk 模組。系統應用無法排除；變更於該應用下次啟動時生效。",
    exclude_unmount: "同時卸載模組掛載",
    exclude_unmount_hint: "對已排除的應用隱藏模組掛載，效果同 DenyList",
    search_apps: "搜尋名稱或套件名",
    user_apps: "使用者應用",
    filter_all: "全部",
    filter_excluded: "已排除",
    apps_loading: "正在載入應用…",
    apps_failed: "無法取得應用清單",
    apps_none: "沒有使用者應用",
    apps_no_match: "沒有符合的應用",
    pending_restart: "待重啟",
    shared_uid: "與另外 {n} 個套件共用 UID，會一起切換",
    shared_uid_system: "與系統套件共用 UID，無法排除",
  },
  "zh-Hans": {
    language: "语言",
    tabs: "标签页",
    tab_overview: "概览",
    info: "设备与环境",
    modules: "已启用模块",
    settings: "设置",
    monitor: "Zygote 监控",
    zygote: "Zygote",
    daemon: "守护进程",
    root: "Root 方案",
    rom: "系统",
    kernel: "内核",
    sdk: "Android SDK",
    abi: "ABI",
    running: "运行中",
    tracing: "追踪中",
    stopped: "已停止",
    exited: "已退出",
    injected: "已注入",
    not_injected: "未注入",
    crashed: "已崩溃",
    unknown: "未知",
    status_ok: "运行正常",
    status_ok_hint: "所有组件已注入并在运行",
    status_warn: "部分异常",
    status_warn_hint: "有组件未在运行，模块可能无法加载",
    status_down: "未运行",
    status_down_hint: "Zygisk 未启用，请尝试重启设备",
    status_unknown: "状态未知",
    status_unknown_hint: "无法读取当前状态",
    reload: "刷新",
    modules_none: "没有已启用的 Zygisk 模块",
    target: "目标",
    by_author: "作者",
    reloaded: "已刷新",
    saved: "已保存",
    load_failed: "读取模块状态失败",
    save_failed: "保存设置失败",
    bridge_missing: "找不到支持的 WebUI bridge",
    anonymous_memory: "匿名内存",
    anonymous_memory_hint: "特化后隐藏模块的内存映射",
    custom_linker: "自定义链接器",
    custom_linker_hint: "不经过系统链接器加载模块（实验性）",
    plt_engine: "PLT Hook 引擎",
    plt_engine_hint: "ZN 模块的 PLT Hook 实现",
    app_exclude: "应用排除",
    app_exclude_hint: "勾选的用户应用不加载任何 Zygisk 模块。系统应用无法排除；更改在该应用下次启动时生效。",
    exclude_unmount: "同时卸载模块挂载",
    exclude_unmount_hint: "对已排除的应用隐藏模块挂载，效果同 DenyList",
    search_apps: "搜索名称或包名",
    user_apps: "用户应用",
    filter_all: "全部",
    filter_excluded: "已排除",
    apps_loading: "正在加载应用…",
    apps_failed: "无法获取应用列表",
    apps_none: "没有用户应用",
    apps_no_match: "没有匹配的应用",
    pending_restart: "待重启",
    shared_uid: "与另外 {n} 个包共用 UID，会一起切换",
    shared_uid_system: "与系统包共用 UID，无法排除",
  },
};

let currentLang = pickInitialLanguage();
let currentTab = "overview";
let currentPltEngine = "bytehook";
let toastTimer = null;
let refreshing = false;
// Last successful status snapshot, kept so a language switch re-renders without a shell round trip.
let snapshot = null;

// User apps as { pkg, label, appId }, plus every installed package grouped by app id.
let userApps = [];
let appIdGroups = new Map();
let userPackages = new Set();
let appsState = "loading";
let appFilter = "all";

// excludedApps is what the UI shows; savedExcluded is what config.prop holds. initialExcluded
// is the list when the page opened, used to flag apps that need a restart.
let excludedApps = new Set();
let savedExcluded = new Set();
let initialExcluded = null;

// Every config.prop write goes through this chain so concurrent toggles cannot clobber the
// shared temp file or each other's keys.
let configWrite = Promise.resolve();

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("lang-select").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-lang]");
    if (button && button.dataset.lang !== currentLang) {
      currentLang = button.dataset.lang;
      try {
        localStorage.setItem(LANG_STORAGE_KEY, currentLang);
      } catch (_) {
        // Storage may be unavailable in some WebViews; the choice then lasts this session.
      }
      applyTranslations();
    }
  });

  $("plt-engine-select").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-engine]");
    if (button && button.dataset.engine !== currentPltEngine) {
      const newEngine = button.dataset.engine;
      currentPltEngine = newEngine;
      updatePltEngineButtons();
      const result = await queueConfigWrite("plt_engine", () => newEngine);
      if (result && result.code === 0) {
        showToast("saved");
      } else {
        showToast("save_failed", true);
      }
    }
  });

  document.querySelector(".tabbar").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-tab]");
    if (button) {
      setTab(button.dataset.tab);
    }
  });

  $("btn-reload").addEventListener("click", () => {
    refresh(true);
  });
  $("anonymous-memory").addEventListener("change", (event) => {
    saveToggle(event.target, "anonymous_memory");
  });
  $("custom-linker").addEventListener("change", (event) => {
    saveToggle(event.target, "custom_linker");
  });
  $("exclude-unmount").addEventListener("change", (event) => {
    saveToggle(event.target, "exclude_unmount");
  });
  $("app-search").addEventListener("input", () => {
    renderApps();
  });
  $("app-filter").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-filter]");
    if (button) {
      appFilter = button.dataset.filter;
      renderApps();
    }
  });
  $("app-list").addEventListener("change", (event) => {
    const input = event.target;
    if (input && input.dataset && input.dataset.pkg) {
      toggleApp(input.dataset.pkg, input.checked);
    }
  });

  setTab(currentTab);
  applyTranslations();
  refresh(false);
});

function pickInitialLanguage() {
  try {
    const stored = localStorage.getItem(LANG_STORAGE_KEY);
    if (stored && I18N[stored]) {
      return stored;
    }
  } catch (_) {
    // Fall through to the browser language.
  }
  const language = navigator.language || "en";
  if (language.startsWith("zh")) {
    return /hans|cn|sg/i.test(language) ? "zh-Hans" : "zh-Hant";
  }
  return "en";
}

function t(key, vars) {
  const local = I18N[currentLang] || I18N.en;
  let text = local[key] !== undefined ? local[key] : (I18N.en[key] !== undefined ? I18N.en[key] : key);
  if (vars) {
    Object.keys(vars).forEach((name) => {
      text = text.replace(`{${name}}`, vars[name]);
    });
  }
  return text;
}

function applyTranslations() {
  document.documentElement.lang = currentLang;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.placeholder = t(element.getAttribute("data-i18n-placeholder"));
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
    element.setAttribute("aria-label", t(element.getAttribute("data-i18n-aria")));
  });
  document.querySelectorAll("#lang-select button").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.lang === currentLang));
  });
  updatePltEngineButtons();

  renderOverview();
  renderApps();
}

function updatePltEngineButtons() {
  document.querySelectorAll("#plt-engine-select button").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.engine === currentPltEngine));
  });
}

function setTab(tab) {
  currentTab = tab;
  $("view-overview").hidden = tab !== "overview";
  $("view-apps").hidden = tab !== "apps";
  document.querySelectorAll(".tabbar button").forEach((button) => {
    if (button.dataset.tab === tab) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });
  window.scrollTo(0, 0);
}

function parseProp(text) {
  const data = {};
  text.split(/\r?\n/).forEach((line) => {
    const match = line.trim().match(/^([^=]+)=(.*)$/);
    if (!match) {
      return;
    }
    data[match[1].trim()] = match[2].trim();
  });
  return data;
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getExec() {
  const exec = window.NeoZygiskWebUi && window.NeoZygiskWebUi.exec;
  return typeof exec === "function" ? exec : null;
}

// ---------------------------------------------------------------------------
// Status

function normalizeStatus(status) {
  return status || "unknown";
}

function renderStatus(id, status) {
  const element = $(id);
  const normalized = normalizeStatus(status);
  element.textContent = t(normalized);
  element.className = "value";
  if (GOOD_STATUSES.has(normalized)) {
    element.classList.add("value-good");
  } else if (BAD_STATUSES.has(normalized)) {
    element.classList.add("value-danger");
  }
}

function overallTone(monitor, zygote, daemon) {
  const all = [monitor, zygote, daemon];
  if (all.every((s) => GOOD_STATUSES.has(s))) {
    return "ok";
  }
  if (BAD_STATUSES.has(monitor) || BAD_STATUSES.has(zygote)) {
    return "down";
  }
  if (all.some((s) => BAD_STATUSES.has(s))) {
    return "warn";
  }
  return "unknown";
}

function renderHero(tone) {
  const classes = { ok: "tone-ok", warn: "tone-warn", down: "tone-down", unknown: "tone-neutral" };
  $("hero").className = `hero ${classes[tone]}`;
  $("hero-title").textContent = t(`status_${tone}`);
  $("hero-sub").textContent = t(`status_${tone}_hint`);
}

function getAbiStatus(data, prefix) {
  const key = Object.keys(data).find(
    (name) => name.startsWith(`${prefix}_`) && name.endsWith("_status"),
  );
  if (!key) {
    return { rawAbi: "", status: "unknown" };
  }
  return {
    rawAbi: key.slice(prefix.length + 1, -"_status".length),
    status: data[key] || "unknown",
  };
}

function formatAbiLabel(rawAbi) {
  if (!rawAbi) {
    return "";
  }
  const known = {
    "64": "64-bit",
    "32": "32-bit",
    arm64: "64-bit",
    "arm64-v8a": "64-bit",
    "x86_64": "64-bit",
    x86: "32-bit",
    "armeabi-v7a": "32-bit",
  };
  return known[rawAbi] || rawAbi;
}

function normalizeRootName(name) {
  const normalized = String(name || "").trim();
  const names = {
    apatch: "APatch",
    kernelsu: "KernelSU",
    ksu: "KernelSU",
    magisk: "Magisk",
    sukisu: "SukiSU",
  };
  return names[normalized.toLowerCase()] || normalized;
}

function formatRootInfo(rootData, fallback) {
  const name = normalizeRootName(rootData.root);
  if (!name || name === "Unknown") {
    return fallback || "-";
  }
  const version = rootData.version_text || rootData.version;
  return version ? `${name} ${version}` : name;
}

// Vendor skins report their version through their own properties; show whichever is set.
function formatRomInfo(rom) {
  const oplus = rom["ro.build.version.oplusrom.display"] || rom["ro.build.version.oplusrom"];
  if (oplus) {
    return /[a-z]{2,}/i.test(oplus) ? oplus : `ColorOS / OxygenOS ${oplus.replace(/^V/i, "")}`;
  }
  const hyperos = rom["ro.mi.os.version.name"];
  if (hyperos) {
    return `HyperOS ${hyperos.replace(/^OS/i, "")}`;
  }
  const miui = rom["ro.miui.ui.version.name"];
  if (miui) {
    return `MIUI ${miui.replace(/^V/i, "")}`;
  }
  const oneui = Number(rom["ro.build.version.oneui"]);
  if (oneui > 0) {
    return `One UI ${Math.floor(oneui / 10000)}.${Math.floor(oneui / 100) % 100}`;
  }
  return "";
}

// ---------------------------------------------------------------------------
// Modules

// The daemon reports module ids under "name", with type/target/companion metadata.
function parseDaemonModules(data) {
  if (!data.modules_list) {
    return [];
  }
  try {
    const parsed = JSON.parse(data.modules_list);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => {
        if (typeof item === "object" && item !== null) {
          return {
            id: String(item.name || "").trim(),
            type: item.type === "next" ? "next" : "zygisk",
            target: item.target ? String(item.target).trim() : "",
            companion: Boolean(item.companion),
          };
        }
        return { id: String(item).trim(), type: "zygisk", target: "", companion: false };
      }).filter((m) => m.id.length > 0);
    }
  } catch (_) {
    return data.modules_list.split(",").map((item) => ({
      id: item.trim(),
      type: "zygisk",
      target: "",
      companion: false,
    })).filter((m) => m.id.length > 0);
  }
  return [];
}

// Splits the module scan into { id, props } blocks. Markers must start a line, so a "###"
// or similar inside a module.prop description cannot break the split.
function parseModuleScan(rawText) {
  const modules = [];
  let current = null;
  rawText.split(/\r?\n/).forEach((line) => {
    if (line.startsWith(MODULE_MARKER)) {
      current = { id: line.slice(MODULE_MARKER.length).trim(), lines: [] };
      modules.push(current);
    } else if (current) {
      current.lines.push(line);
    }
  });
  return modules.filter((m) => m.id).map((m) => {
    const props = parseProp(m.lines.join("\n"));
    return {
      id: m.id,
      name: props.name || m.id,
      version: props.version || "",
      author: props.author || "",
      description: props.description || "",
    };
  });
}

// Merges the filesystem scan (names, versions, descriptions) with the daemon's view
// (ZN type, targets, companions) keyed by module id.
function mergeModules(scanned, reported) {
  const byId = new Map(reported.map((m) => [m.id, m]));
  const merged = scanned.map((mod) => {
    const info = byId.get(mod.id);
    byId.delete(mod.id);
    return {
      ...mod,
      type: info ? info.type : "zygisk",
      target: info ? info.target : "",
      companion: info ? info.companion : false,
    };
  });
  byId.forEach((info) => {
    merged.push({ id: info.id, name: info.id, version: "", author: "", description: "", ...info });
  });
  return merged;
}

function renderModules(modules) {
  const list = $("module-list");
  $("v-modules-count").textContent = String(modules.length);
  if (!modules.length) {
    list.innerHTML = `<p class="empty">${escapeHtml(t("modules_none"))}</p>`;
    return;
  }

  list.innerHTML = modules.map((mod) => {
    const isNext = mod.type === "next";
    const badges = [
      `<span class="badge ${isNext ? "badge-next" : "badge-zygisk"}">${isNext ? "ZN" : "Zygisk"}</span>`,
    ];
    if (mod.companion) {
      badges.push(`<span class="badge badge-companion">Companion</span>`);
    }
    const meta = [];
    if (isNext && mod.target && mod.target !== "zygote") {
      meta.push(`<span>${escapeHtml(t("target"))}: <span class="mono">${escapeHtml(mod.target)}</span></span>`);
    }
    if (mod.author) {
      meta.push(`<span>${escapeHtml(t("by_author"))} ${escapeHtml(mod.author)}</span>`);
    }

    return `
      <article class="module">
        <div class="module-head">
          <h3 class="module-name">${escapeHtml(mod.name)}</h3>
          ${mod.version ? `<span class="module-version">${escapeHtml(mod.version)}</span>` : ""}
        </div>
        ${mod.description ? `<p class="module-desc">${escapeHtml(mod.description)}</p>` : ""}
        <div class="module-meta">${badges.join("")}${meta.join(" · ")}</div>
      </article>
    `;
  }).join("");
}

// ---------------------------------------------------------------------------
// Status command

function decodeBase64Utf8(b64) {
  if (!b64) return "";
  try {
    const binary = atob(b64.replace(/\s+/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch (e) {
    console.error("Base64 decode error:", e);
    return "";
  }
}

function parseSectionOutput(stdout) {
  const sections = {};
  let currentSection = null;
  const buffer = [];

  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("---") && trimmed.endsWith("---") && trimmed.length > 6) {
      if (currentSection) {
        sections[currentSection] = buffer.join("");
        buffer.length = 0;
      }
      currentSection = trimmed.slice(3, -3);
    } else if (currentSection && trimmed.length > 0) {
      buffer.push(trimmed);
    }
  }
  if (currentSection) {
    sections[currentSection] = buffer.join("");
  }

  return {
    prop: decodeBase64Utf8(sections.PROP || ""),
    root: decodeBase64Utf8(sections.ROOT || ""),
    rom: decodeBase64Utf8(sections.ROM || ""),
    config: decodeBase64Utf8(sections.CONFIG || ""),
    modules: decodeBase64Utf8(sections.MODULES || ""),
  };
}

function unifiedStatusCommand() {
  return [
    'dump_all() {',
    '  echo "---PROP---"',
    `  base64 < ${PROP_PATH} 2>/dev/null`,
    '  echo "---ROOT---"',
    '  {',
    '    r="Unknown"',
    '    pidof apd >/dev/null 2>&1 && r="APatch"',
    '    pidof fpd >/dev/null 2>&1 && r="FolkPatch"',
    '    [ -d /data/adb/ksu ] && r="KernelSU"',
    '    pidof magiskd >/dev/null 2>&1 && r="Magisk"',
    '    echo "root=$r"',
    '    if [ "$r" = "APatch" ] || [ "$r" = "FolkPatch" ]; then',
    '      if command -v apd >/dev/null 2>&1; then',
    '        v=$(apd -V 2>/dev/null | head -n 1)',
    '        [ -n "$v" ] && echo "version_text=$v"',
    '      fi',
    '    elif [ "$r" = "KernelSU" ]; then',
    '      if command -v ksud >/dev/null 2>&1; then',
    '        v=$(ksud -V 2>/dev/null | head -n 1)',
    '        [ -n "$v" ] && echo "version_text=$v"',
    '      fi',
    '    elif [ "$r" = "Magisk" ]; then',
    '      if command -v magisk >/dev/null 2>&1; then',
    '        v=$(magisk -v 2>/dev/null | head -n 1)',
    '        [ -n "$v" ] && echo "version_text=$v"',
    '      fi',
    '    fi',
    '  } | base64',
    '  echo "---ROM---"',
    '  {',
    '    for p in ro.build.version.oplusrom.display ro.build.version.oplusrom ro.mi.os.version.name ro.miui.ui.version.name ro.build.version.oneui; do',
    '      v=$(getprop "$p")',
    '      [ -n "$v" ] && echo "$p=$v"',
    '    done',
    '  } | base64',
    '  echo "---CONFIG---"',
    `  base64 < ${CONFIG_PATH} 2>/dev/null`,
    '  echo "---MODULES---"',
    '  {',
    '    for d in /data/adb/modules/*; do',
    '      [ -d "$d" ] || continue',
    '      [ -f "$d/disable" ] && continue',
    '      [ -f "$d/remove" ] && continue',
    '      has_zy=0',
    '      if [ -f "$d/zygisk/arm64-v8a.so" ] || [ -f "$d/zygisk/armeabi-v7a.so" ] || [ -f "$d/zygisk/x86_64.so" ] || [ -f "$d/zygisk/x86.so" ] || [ -f "$d/zn_modules.txt" ]; then',
    '        has_zy=1',
    '      fi',
    '      [ "$has_zy" -eq 1 ] || continue',
    `      echo "${MODULE_MARKER}\${d##*/}"`,
    '      cat "$d/module.prop" 2>/dev/null',
    '      echo',
    '    done',
    '  } | base64',
    '}',
    'dump_all',
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Refresh

function showToast(key, isError = false) {
  const toast = $("toast");
  toast.textContent = t(key);
  toast.className = `toast${isError ? " error" : ""}`;
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    toast.className = "toast hidden";
  }, isError ? 2600 : 1200);
}

function setLoading(loading) {
  refreshing = loading;
  $("btn-reload").disabled = loading;
  $("btn-reload").classList.toggle("loading", loading);
}

async function refresh(showSuccessToast) {
  if (refreshing) {
    return;
  }
  const exec = getExec();
  if (!exec) {
    snapshot = null;
    appsState = "failed";
    renderOverview();
    renderApps();
    showToast("bridge_missing", true);
    return;
  }

  setLoading(true);
  try {
    // Never read config.prop while a write is still in flight.
    await configWrite;
    const writeBeforeRead = configWrite;
    const result = await exec(unifiedStatusCommand());
    if (result.code !== 0 && !result.stdout) {
      snapshot = null;
      renderOverview();
      showToast(String(result.stderr).includes("No supported") ? "bridge_missing" : "load_failed", true);
      return;
    }

    const sections = parseSectionOutput(result.stdout);
    const data = parseProp(sections.prop);
    snapshot = {
      data,
      root: parseProp(sections.root),
      rom: parseProp(sections.rom),
      modules: mergeModules(parseModuleScan(sections.modules), parseDaemonModules(data)),
    };
    renderOverview();

    // A toggle queued while the status command ran is newer than what it read, so keep
    // the UI state instead of overwriting it with the stale config.prop snapshot.
    if (configWrite === writeBeforeRead) {
      const config = parseProp(sections.config);
      $("anonymous-memory").checked = config.anonymous_memory === "1";
      $("custom-linker").checked = config.custom_linker === "1";
      $("exclude-unmount").checked = config.exclude_unmount !== "0";
      currentPltEngine = config.plt_engine === "lsplt" ? "lsplt" : "bytehook";
      updatePltEngineButtons();
      savedExcluded = new Set(
        (config.exclude_apps || "").split(",").map((p) => p.trim()).filter(Boolean),
      );
      excludedApps = new Set(savedExcluded);
      if (!initialExcluded) {
        initialExcluded = new Set(savedExcluded);
      }
    }

    if (appsState !== "ready" || showSuccessToast) {
      await loadApps();
    } else {
      renderApps();
    }

    if (showSuccessToast) {
      showToast("reloaded");
    }
  } finally {
    setLoading(false);
  }
}

function renderOverview() {
  if (!snapshot) {
    renderFailure();
    return;
  }
  const { data, root, rom, modules } = snapshot;

  const rootText = formatRootInfo(root, data.root_implementation);
  $("v-root").textContent = rootText;
  const romText = formatRomInfo(rom);
  $("v-rom").textContent = romText || "-";
  $("t-rom").hidden = !romText;
  $("v-kernel").textContent = data.device_kernel || "-";
  $("v-sdk").textContent = data.device_sdk || "-";
  $("v-abi").textContent = data.device_abi || "-";
  $("v-subtitle").textContent = [data.version, rootText !== "-" ? rootText : ""]
    .filter(Boolean).join(" · ") || "-";

  const monitor = normalizeStatus(data.monitor_status);
  const zygote = getAbiStatus(data, "zygote");
  const daemon = getAbiStatus(data, "daemon");
  const abiLabel = formatAbiLabel(zygote.rawAbi || daemon.rawAbi);
  $("l-zygote").textContent = abiLabel ? `${t("zygote")} (${abiLabel})` : t("zygote");
  $("l-daemon").textContent = abiLabel ? `${t("daemon")} (${abiLabel})` : t("daemon");
  renderStatus("v-monitor", monitor);
  renderStatus("v-zygote", zygote.status);
  renderStatus("v-daemon", daemon.status);
  renderHero(overallTone(monitor, zygote.status, daemon.status));

  renderModules(modules);
}

function renderFailure() {
  renderStatus("v-monitor", "unknown");
  renderStatus("v-zygote", "unknown");
  renderStatus("v-daemon", "unknown");
  renderHero("unknown");
  $("v-subtitle").textContent = "-";
  $("v-root").textContent = "-";
  $("v-kernel").textContent = "-";
  $("v-sdk").textContent = "-";
  $("v-abi").textContent = "-";
  $("l-zygote").textContent = t("zygote");
  $("l-daemon").textContent = t("daemon");
  renderModules([]);
}

// ---------------------------------------------------------------------------
// Config writes

// Writes one key of config.prop atomically, keeping every other key. Callers must pass a
// value made only of [A-Za-z0-9_.,] so it can sit inside single quotes.
function setConfigValue(key, value) {
  const exec = getExec();
  if (!exec || !/^[A-Za-z0-9_.,]*$/.test(value)) {
    return Promise.resolve({ code: 1 });
  }
  return exec(
    `mkdir -p ${CONFIG_DIR} && ` +
    `{ if [ -f ${CONFIG_PATH} ]; then grep -v '^${key}=' ${CONFIG_PATH}; fi; ` +
    `printf '${key}=${value}\\n'; } > ${CONFIG_PATH}.tmp && ` +
    `mv ${CONFIG_PATH}.tmp ${CONFIG_PATH} && chmod 0644 ${CONFIG_PATH}`,
  );
}

// Queues a write; getValue runs when the write starts, so it always sees the latest state.
function queueConfigWrite(key, getValue) {
  const run = configWrite.then(() => setConfigValue(key, getValue()));
  configWrite = run.catch(() => {});
  return run;
}

async function saveToggle(input, key) {
  const enabled = input.checked;
  input.disabled = true;
  const result = await queueConfigWrite(key, () => (enabled ? "1" : "0"));
  input.disabled = false;

  if (result.code !== 0) {
    input.checked = !enabled;
    showToast("save_failed", true);
    return;
  }
  showToast("saved");
}

// ---------------------------------------------------------------------------
// App exclusion

function appsCommand() {
  return [
    'pm list packages -3 2>/dev/null',
    'echo "---UIDS---"',
    `cut -d' ' -f1,2 ${PACKAGES_LIST_PATH} 2>/dev/null`,
  ].join("\n");
}

// Uses the KernelSU WebUI package API for display names when the manager provides it.
function loadAppLabels(packages) {
  const bridge = window.ksu;
  if (!bridge || typeof bridge.getPackagesInfo !== "function" || !packages.length) {
    return {};
  }
  try {
    const info = JSON.parse(bridge.getPackagesInfo(JSON.stringify(packages)));
    const labels = {};
    (Array.isArray(info) ? info : []).forEach((item) => {
      if (item && item.packageName && item.appLabel) {
        labels[item.packageName] = String(item.appLabel);
      }
    });
    return labels;
  } catch (_) {
    return {};
  }
}

async function loadApps() {
  const exec = getExec();
  if (!exec) {
    return;
  }

  const result = await exec(appsCommand());
  if (result.code !== 0 && !result.stdout) {
    appsState = "failed";
    renderApps();
    showToast("apps_failed", true);
    return;
  }

  const [pmPart, uidPart = ""] = result.stdout.split("---UIDS---");
  const packages = pmPart
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^package:/, ""))
    .filter((pkg) => PACKAGE_RE.test(pkg));

  // Mirror the daemon: packages sharing an app id are excluded together or not at all.
  const appIdOf = new Map();
  appIdGroups = new Map();
  uidPart.split(/\r?\n/).forEach((line) => {
    const [pkg, uid] = line.trim().split(/\s+/);
    const appId = Number(uid) % 100000;
    if (!pkg || !Number.isFinite(appId)) {
      return;
    }
    appIdOf.set(pkg, appId);
    if (appId >= 10000 && appId <= 19999) {
      if (!appIdGroups.has(appId)) {
        appIdGroups.set(appId, []);
      }
      appIdGroups.get(appId).push(pkg);
    }
  });
  userPackages = new Set(packages);

  const labels = loadAppLabels(packages);
  userApps = packages.map((pkg) => ({
    pkg,
    label: labels[pkg] || "",
    appId: appIdOf.has(pkg) ? appIdOf.get(pkg) : null,
  }));
  appsState = "ready";
  renderApps();
}

function groupOf(app) {
  const group = app.appId !== null ? appIdGroups.get(app.appId) : null;
  return group && group.length ? group : [app.pkg];
}

// An app whose UID is shared with a system package cannot be excluded: the daemon excludes
// a UID only when every package on it is listed, and system packages must never be listed.
function isLocked(app) {
  return groupOf(app).some((pkg) => !userPackages.has(pkg));
}

function excludedUserCount() {
  if (appsState !== "ready") {
    return excludedApps.size;
  }
  return userApps.filter((app) => excludedApps.has(app.pkg) && !isLocked(app)).length;
}

function isPending(pkg) {
  return Boolean(initialExcluded) && excludedApps.has(pkg) !== initialExcluded.has(pkg);
}

function renderAppCounts() {
  const excluded = excludedUserCount();
  $("v-excluded-count").textContent = String(excluded);
  const filterButtons = $("app-filter").querySelectorAll("button");
  filterButtons[0].textContent = `${t("filter_all")} ${appsState === "ready" ? userApps.length : ""}`.trim();
  filterButtons[1].textContent = `${t("filter_excluded")} ${excluded}`;
  filterButtons.forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.filter === appFilter));
  });
}

function renderApps() {
  const list = $("app-list");
  renderAppCounts();

  if (appsState !== "ready") {
    const key = appsState === "failed" ? "apps_failed" : "apps_loading";
    list.innerHTML = `<p class="empty">${escapeHtml(t(key))}</p>`;
    return;
  }

  const query = $("app-search").value.trim().toLowerCase();
  const apps = userApps
    .filter((app) => appFilter === "all" || (excludedApps.has(app.pkg) && !isLocked(app)))
    .filter((app) => !query || app.pkg.toLowerCase().includes(query) || app.label.toLowerCase().includes(query))
    .sort((a, b) => (excludedApps.has(b.pkg) - excludedApps.has(a.pkg))
      || (a.label || a.pkg).localeCompare(b.label || b.pkg));

  if (!apps.length) {
    const key = userApps.length ? "apps_no_match" : "apps_none";
    list.innerHTML = `<p class="empty">${escapeHtml(t(key))}</p>`;
    return;
  }

  list.innerHTML = apps.map((app) => {
    const title = app.label || app.pkg;
    const initial = (title.replace(/^[^A-Za-z0-9\p{L}]+/u, "").charAt(0) || "?").toUpperCase();
    const shared = groupOf(app).length - 1;
    const locked = isLocked(app);
    let note = "";
    if (locked) {
      note = t("shared_uid_system");
    } else if (shared > 0) {
      note = t("shared_uid", { n: shared });
    }
    return `
      <label class="toggle-row app-row">
        <input type="checkbox" role="switch" data-pkg="${escapeHtml(app.pkg)}"${excludedApps.has(app.pkg) && !locked ? " checked" : ""}${locked ? " disabled" : ""}>
        <span class="avatar" aria-hidden="true">${escapeHtml(initial)}</span>
        <span class="app-text">
          <span class="app-title">
            <span class="app-label">${escapeHtml(title)}</span>
            <span class="badge badge-warn" data-pending-for="${escapeHtml(app.pkg)}"${isPending(app.pkg) ? "" : " hidden"}>${escapeHtml(t("pending_restart"))}</span>
          </span>
          ${app.label ? `<span class="app-pkg">${escapeHtml(app.pkg)}</span>` : ""}
          ${note ? `<span class="app-note">${escapeHtml(note)}</span>` : ""}
        </span>
        <span class="switch" aria-hidden="true"></span>
      </label>
    `;
  }).join("");
}

// Updates rows in place instead of re-rendering, so a toggled row does not jump away
// from under the user's finger when the list re-sorts.
function syncAppRows(packages) {
  packages.forEach((pkg) => {
    const input = $("app-list").querySelector(`input[data-pkg="${CSS.escape(pkg)}"]`);
    if (input) {
      input.checked = excludedApps.has(pkg);
    }
    const badge = $("app-list").querySelector(`[data-pending-for="${CSS.escape(pkg)}"]`);
    if (badge) {
      badge.hidden = !isPending(pkg);
    }
  });
  renderAppCounts();
}

async function toggleApp(pkg, excluded) {
  const app = userApps.find((item) => item.pkg === pkg) || { pkg, appId: null };
  if (isLocked(app)) {
    return;
  }
  const group = groupOf(app);
  group.forEach((member) => {
    if (excluded) {
      excludedApps.add(member);
    } else {
      excludedApps.delete(member);
    }
  });
  syncAppRows(group);

  // Drop packages that are no longer installed so the list never holds invisible entries.
  let written = "";
  const result = await queueConfigWrite("exclude_apps", () => {
    written = [...excludedApps]
      .filter((p) => userPackages.has(p) && PACKAGE_RE.test(p))
      .sort()
      .join(",");
    return written;
  });

  if (result.code !== 0) {
    excludedApps = new Set(savedExcluded);
    renderApps();
    showToast("save_failed", true);
    return;
  }
  savedExcluded = new Set(written ? written.split(",") : []);
  showToast("saved");
}
