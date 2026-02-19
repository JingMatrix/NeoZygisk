import { exec } from "./kernelsu.js";

const translations = {
    en: {
        basic_info: "Basic Information",
        kernel: "Kernel",
        author: "Author",
        description: "Description",
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
    },
    zh: {
        basic_info: "\u57fa\u672c\u4fe1\u606f",
        kernel: "\u5185\u6838",
        author: "\u4f5c\u8005",
        description: "\u63cf\u8ff0",
        dashboard: "\u4eea\u8868\u677f",
        root_impl: "Root \u5b9e\u73b0",
        zygote_monitor: "Zygote \u76d1\u89c6\u5668",
        running: "\u8fd0\u884c\u4e2d",
        injected: "\u5df2\u6ce8\u5165",
        modules: "\u6a21\u5757",
        modules_list: "\u8fd0\u884c\u4e2d\u7684\u6a21\u5757",
        tracing: "\u8ffd\u8e2a\u4e2d",
        stopped: "\u5df2\u505c\u6b62",
        exited: "\u5df2\u9000\u51fa",
        unknown: "\u672a\u77e5",
        not_injected: "\u672a\u6ce8\u5165",
        crashed: "\u5df2\u5d29\u6e83",
        refreshed: "\u5df2\u5237\u65b0",
    },
};

let currentLang = "en";
let toastTimer = null;

document.addEventListener("DOMContentLoaded", () => {
    const langBtn = document.getElementById("lang-btn");
    const langDropdown = document.getElementById("lang-dropdown");
    const langOptions = document.querySelectorAll(".dropdown-menu button");
    const refreshBtn = document.getElementById("refresh-btn");
    const modulesLink = document.getElementById("modules-link");

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
            fetchAndParseModuleProp();
            showToast("refreshed");
        });
    }

    if (modulesLink) {
        modulesLink.addEventListener("click", () => {
            const list = document.getElementById("modules-list");
            const arrow = document.getElementById("modules-arrow");
            if (!list) return;

            list.classList.toggle("collapsed");
            list.classList.toggle("expanded");
            if (arrow) arrow.classList.toggle("rotate-180");
        });
    }

    const userLang = navigator.language.startsWith("zh") ? "zh" : "en";
    setLanguage(userLang);
    fetchAndParseModuleProp();
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

function showToast(messageKey) {
    const toast = document.querySelector(".toast");
    if (!toast) return;

    const text = toast.querySelector(".toast-content span:last-child");
    if (text) text.textContent = t(messageKey);

    toast.classList.remove("hidden");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add("hidden"), 1000);
}

async function fetchAndParseModuleProp() {
    try {
        const result = await exec("cat /data/adb/neozygisk/module.prop");
        if (result.errno === 0 && result.stdout) {
            parseModuleProp(result.stdout);
        } else {
            console.error("Failed to read module.prop:", result.stderr);
            updateText("prop-name", "NeoZygisk (Load Failed)");
        }
    } catch (error) {
        console.error("Exec failed:", error);
        updateText("prop-name", "NeoZygisk (Error)");
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
}

function updateText(id, value) {
    if (!isDefined(value)) return;
    const element = document.getElementById(id);
    if (element) element.textContent = String(value);
}

function isDefined(value) {
    return value !== undefined && value !== null;
}

function updateStatusBadge(elementId, statusKey) {
    const element = document.getElementById(elementId);
    if (!element) return;

    element.textContent = t(statusKey);

    const iconCheck = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M22 11.08V12a10 10 0 1 1-5.93-9.14\"></path><polyline points=\"22 4 12 14.01 9 11.01\"></polyline></svg>";
    const iconError = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"10\"></circle><line x1=\"15\" y1=\"9\" x2=\"9\" y2=\"15\"></line><line x1=\"9\" y1=\"9\" x2=\"15\" y2=\"15\"></line></svg>";
    const iconUnknown = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"10\"></circle><line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"12\"></line><line x1=\"12\" y1=\"16\" x2=\"12.01\" y2=\"16\"></line></svg>";

    const badge = element.parentElement;
    if (!badge || !badge.classList.contains("badge")) return;

    badge.setAttribute("data-status", statusKey);
    badge.classList.remove("green", "red", "gray");

    let iconElement = badge.querySelector("svg");
    if (!iconElement) {
        const placeholder = document.createElement("span");
        badge.insertBefore(placeholder, badge.firstChild);
        iconElement = placeholder;
    }

    if (["running", "injected", "tracing"].includes(statusKey)) {
        badge.classList.add("green");
        if (iconElement.outerHTML !== iconCheck) iconElement.outerHTML = iconCheck;
    } else if (["crashed", "not_injected", "stopped", "exited"].includes(statusKey)) {
        badge.classList.add("red");
        if (iconElement.outerHTML !== iconError) iconElement.outerHTML = iconError;
    } else {
        badge.classList.add("gray");
        if (iconElement.outerHTML !== iconUnknown) iconElement.outerHTML = iconUnknown;
    }
}
