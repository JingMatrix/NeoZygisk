import { exec } from "./kernelsu.js";

const translations = {
    en: {
        basic_info: "Basic Information",
        kernel: "Kernel",
        dashboard: "Dashboard",
        root_impl: "Root implementation",
        zygote_monitor: "Zygote Monitor",
        running: "Running",
        injected: "Injected",
        modules: "Modules",
        modules_list: "Running Modules",
        tracing: "Tracing",
        stopped: "Stopped",
        exited: "Exited",
        unknown: "Unknown",
        not_injected: "Not Injected",
        crashed: "Crashed",
        refreshed: "Refreshed",
        load_failed: "Failed to load module.prop",
    },
    zh: {
        basic_info: "基本信息",
        kernel: "内核",
        dashboard: "仪表板",
        root_impl: "Root 实现",
        zygote_monitor: "Zygote 监视器",
        running: "运行中",
        injected: "已注入",
        modules: "模块",
        modules_list: "运行中的模块",
        tracing: "追踪中",
        stopped: "已停止",
        exited: "已退出",
        unknown: "未知",
        not_injected: "未注入",
        crashed: "已崩溃",
        refreshed: "已刷新",
        load_failed: "读取 module.prop 失败",
    },
};

const STATUS_ICON_BY_LEVEL = {
    positive: "icon-status-check",
    negative: "icon-status-x",
    neutral: "icon-status-unknown",
};

const POSITIVE_STATUSES = new Set(["running", "injected", "tracing"]);
const NEGATIVE_STATUSES = new Set(["crashed", "not_injected", "stopped", "exited"]);

let currentLang = "en";
let toastTimer = null;

document.addEventListener("DOMContentLoaded", () => {
    const langBtn = document.getElementById("lang-btn");
    const langDropdown = document.getElementById("lang-dropdown");
    const langOptions = document.querySelectorAll(".dropdown-menu button");
    const refreshBtn = document.getElementById("refresh-btn");
    const modulesLink = document.getElementById("modules-link");
    const modulesList = document.getElementById("modules-list");

    if (langBtn && langDropdown) {
        langBtn.addEventListener("click", (event) => {
            event.stopPropagation();
            langDropdown.classList.toggle("hidden");
        });
        document.addEventListener("click", () => langDropdown.classList.add("hidden"));
    }

    langOptions.forEach((button) => {
        button.addEventListener("click", () => {
            setLanguage(button.getAttribute("data-lang"));
        });
    });

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            fetchAndParseModuleProp(true);
        });
    }

    if (modulesLink && modulesList) {
        modulesLink.addEventListener("click", () => {
            const arrow = document.getElementById("modules-arrow");
            if (modulesList.classList.contains("collapsed")) {
                expandModulesList(modulesList);
            } else {
                collapseModulesList(modulesList);
            }
            if (arrow) arrow.classList.toggle("rotate-180");
        });

        window.addEventListener("resize", () => {
            syncModulesListHeight(modulesList);
        });
    }

    const userLang = navigator.language.startsWith("zh") ? "zh" : "en";
    setLanguage(userLang);
    fetchAndParseModuleProp(false);
});

function setLanguage(lang) {
    currentLang = translations[lang] ? lang : "en";
    const elements = document.querySelectorAll("[data-i18n]");
    elements.forEach((element) => {
        const key = element.getAttribute("data-i18n");
        element.textContent = t(key);
    });

    const badges = document.querySelectorAll(".badge[data-status]");
    badges.forEach((badge) => {
        const statusKey = badge.getAttribute("data-status");
        const valueElement = badge.querySelector("span[id^=\"val-\"]");
        if (valueElement && statusKey) valueElement.textContent = t(statusKey);
    });
}

function t(key) {
    return translations[currentLang]?.[key] || translations.en[key] || key || "";
}

function showToast(messageKey, type = "success") {
    const toast = document.querySelector(".toast");
    if (!toast) return;

    const text = toast.querySelector(".toast-content span:last-child");
    if (text) text.textContent = t(messageKey);

    toast.classList.remove("hidden", "success", "error");
    toast.classList.add(type === "error" ? "error" : "success");

    const toastUse = document.querySelector("#toast-symbol use");
    if (toastUse) {
        setUseHref(toastUse, type === "error" ? STATUS_ICON_BY_LEVEL.negative : STATUS_ICON_BY_LEVEL.positive);
    }

    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        toast.classList.add("hidden");
    }, type === "error" ? 1600 : 1000);
}

async function fetchAndParseModuleProp(showResultToast = false) {
    try {
        const result = await exec("cat /data/adb/neozygisk/module.prop");
        if (result.errno === 0 && result.stdout) {
            parseModuleProp(result.stdout);
            if (showResultToast) showToast("refreshed", "success");
            return;
        }

        console.error("Failed to read module.prop:", result.stderr);
        updateText("prop-name", "NeoZygisk (Load Failed)");
        showToast("load_failed", "error");
    } catch (error) {
        console.error("Exec failed:", error);
        updateText("prop-name", "NeoZygisk (Error)");
        showToast("load_failed", "error");
    }
}

function parseModuleProp(text) {
    const data = {};
    const kvRegex = /^([^=]+)=(.*)$/;

    text.split("\n").forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        const match = trimmed.match(kvRegex);
        if (!match) return;
        data[match[1].trim()] = match[2].trim();
    });

    updateText("prop-name", data.name);
    updateText("prop-version", data.version);
    updateText("val-root", data.root_implementation);

    updateText("device-kernel", data.device_kernel);
    updateText("device-sdk", data.device_sdk);
    updateText("device-abi", data.device_abi);

    updateStatusBadge("val-monitor", data.monitor_status || "unknown");

    const zygoteStatus = resolveStatusKey(data, "zygote");
    const daemonStatus = resolveStatusKey(data, "daemon");
    updateStatusBadge("val-zygote", zygoteStatus.status || "unknown");
    updateStatusBadge("val-daemon", daemonStatus.status || "unknown");
    updateAbiLabels(zygoteStatus.key || daemonStatus.key);

    const modules = parseModulesList(data.modules_list);
    updateText("val-modules-count", data.modules_count ?? modules.length);
    renderModules(modules);
}

function resolveStatusKey(data, prefix) {
    const preferred = [`${prefix}_64_status`, `${prefix}_32_status`];
    for (const key of preferred) {
        if (isDefined(data[key])) return { key, status: data[key] };
    }

    const dynamicKey = Object.keys(data).find(
        (key) => key.startsWith(`${prefix}_`) && key.endsWith("_status"),
    );
    if (!dynamicKey) return { key: "", status: "" };
    return { key: dynamicKey, status: data[dynamicKey] };
}

function updateAbiLabels(statusKey) {
    const zygoteLabel = document.getElementById("status-zygote-label");
    const daemonLabel = document.getElementById("status-daemon-label");
    const abiLabel = getAbiLabel(statusKey);
    const suffix = abiLabel ? ` (${abiLabel})` : "";
    if (zygoteLabel) zygoteLabel.textContent = `zygote${suffix}`;
    if (daemonLabel) daemonLabel.textContent = `daemon${suffix}`;
}

function getAbiLabel(statusKey) {
    if (!statusKey) return "";
    const parts = statusKey.split("_");
    if (parts.length < 3) return "";
    const rawAbi = parts.slice(1, -1).join("_");
    const abiMap = {
        "64": "64-bit",
        "32": "32-bit",
        arm64: "64-bit",
        "x86_64": "64-bit",
        "armeabi-v7a": "32-bit",
        x86: "32-bit",
    };
    return abiMap[rawAbi] || rawAbi;
}

function parseModulesList(modulesListValue) {
    if (!modulesListValue) return [];

    try {
        const parsed = JSON.parse(modulesListValue);
        if (Array.isArray(parsed)) {
            return parsed
                .map((item) => (typeof item === "string" ? item.trim() : ""))
                .filter(Boolean);
        }
    } catch (_) {
        // Compatibility for older format: module1,module2
    }

    return modulesListValue
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
}

function renderModules(modules) {
    const modulesList = document.getElementById("modules-list");
    if (!modulesList) return;

    modulesList.textContent = "";
    modules.forEach((moduleName) => {
        const item = document.createElement("li");
        item.textContent = moduleName;
        modulesList.appendChild(item);
    });

    syncModulesListHeight(modulesList);
}

function expandModulesList(list) {
    list.classList.remove("collapsed");
    list.classList.add("expanded");
    list.style.maxHeight = `${list.scrollHeight}px`;
}

function collapseModulesList(list) {
    list.style.maxHeight = `${list.scrollHeight}px`;
    requestAnimationFrame(() => {
        list.style.maxHeight = "0px";
    });
    list.classList.remove("expanded");
    list.classList.add("collapsed");
}

function syncModulesListHeight(list) {
    if (list.classList.contains("expanded")) {
        list.style.maxHeight = `${list.scrollHeight}px`;
    } else {
        list.style.maxHeight = "0px";
    }
}

function updateText(id, value) {
    if (!isDefined(value)) return;
    const element = document.getElementById(id);
    if (element) {
        const sanitized = String(value).replace(/[\u0000\uFFFD]+$/g, "");
        element.textContent = sanitized;
    }
}

function isDefined(value) {
    return value !== undefined && value !== null;
}

function updateStatusBadge(elementId, statusKey) {
    const element = document.getElementById(elementId);
    if (!element) return;

    element.textContent = t(statusKey);

    const badge = element.parentElement;
    if (!badge || !badge.classList.contains("badge")) return;

    badge.setAttribute("data-status", statusKey);
    badge.classList.remove("green", "red", "gray");

    const statusLevel = getStatusLevel(statusKey);
    if (statusLevel === "positive") badge.classList.add("green");
    if (statusLevel === "negative") badge.classList.add("red");
    if (statusLevel === "neutral") badge.classList.add("gray");

    const useElement = badge.querySelector(".badge-icon use");
    if (useElement) setUseHref(useElement, STATUS_ICON_BY_LEVEL[statusLevel]);
}

function getStatusLevel(statusKey) {
    if (POSITIVE_STATUSES.has(statusKey)) return "positive";
    if (NEGATIVE_STATUSES.has(statusKey)) return "negative";
    return "neutral";
}

function setUseHref(useElement, symbolId) {
    const reference = `#${symbolId}`;
    useElement.setAttribute("href", reference);
    useElement.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", reference);
}
