import { exec } from './kernelsu.js';

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
        // Statuses
        tracing: "Tracing",
        stopped: "Stopped",
        exited: "Exited",
        unknown: "Unknown",
        not_injected: "Not Injected",
        crashed: "Crashed",
        refreshed: "Refreshed"
    },
    zh: {
        basic_info: "基本信息",
        kernel: "内核",
        author: "作者",
        description: "描述",
        dashboard: "仪表板",
        root_impl: "Root 实现",
        zygote_monitor: "Zygote 监视器",
        running: "运行中",
        injected: "已注入",
        modules: "模块",
        modules_list: "运行中的模块",
        // Statuses
        tracing: "追踪中",
        stopped: "已停止",
        exited: "已退出",
        unknown: "未知",
        not_injected: "未注入",
        crashed: "已崩溃",
        refreshed: "已刷新"
    }
};

document.addEventListener('DOMContentLoaded', () => {
    const langBtn = document.getElementById('lang-btn');
    const langDropdown = document.getElementById('lang-dropdown');
    const langOptions = document.querySelectorAll('.dropdown-menu button');
    const refreshBtn = document.getElementById('refresh-btn');
    const modulesLink = document.getElementById('modules-link');

    // Toggle dropdown
    langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langDropdown.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', () => {
        langDropdown.classList.add('hidden');
    });

    // Language switching
    langOptions.forEach(btn => {
        btn.addEventListener('click', () => {
            const lang = btn.getAttribute('data-lang');
            setLanguage(lang);
        });
    });

    // Refresh button
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            fetchAndParseModuleProp();
            showToast('refreshed');
        });
    }

    // Inline Expand Logic
    if (modulesLink) {
        modulesLink.addEventListener('click', () => {
            const list = document.getElementById('modules-list');
            const arrow = document.getElementById('modules-arrow');

            if (list) {
                if (list.classList.contains('collapsed')) {
                    list.classList.remove('collapsed');
                    list.classList.add('expanded');
                } else {
                    list.classList.remove('expanded');
                    list.classList.add('collapsed');
                }

                if (arrow) {
                    arrow.classList.toggle('rotate-180');
                }
            }
        });
    }

    // Initialize language (default to English or browser lang)
    const userLang = navigator.language.startsWith('zh') ? 'zh' : 'en';
    setLanguage(userLang);

    // Fetch and parse module.prop
    fetchAndParseModuleProp();
});

let currentLang = 'en';

function setLanguage(lang) {
    currentLang = lang;
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[lang] && translations[lang][key]) {
            el.textContent = translations[lang][key];
        }
    });

    // Re-apply status badges to update text
    const badges = document.querySelectorAll('.badge[data-status]');
    badges.forEach(badge => {
        const statusKey = badge.getAttribute('data-status');
        const innerSpan = badge.querySelector('span[id^="val-"]');
        if (innerSpan) {
            const text = translations[currentLang][statusKey] || statusKey;
            innerSpan.textContent = text;
        }
    });
}

function showToast(messageKey) {
    const toast = document.querySelector('.toast');
    if (!toast) return;

    const toastText = toast.querySelector('.toast-content span:last-child');
    if (toastText) {
        const message = translations[currentLang][messageKey] || messageKey;
        toastText.textContent = message;
    }

    toast.classList.remove('hidden');

    // Hide after 1 seconds
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 1000);
}

async function fetchAndParseModuleProp() {
    try {
        const result = await exec('cat /data/adb/neozygisk/module.prop');
        if (result.errno === 0 && result.stdout) {
            parseModuleProp(result.stdout);
            console.log('✓ Successfully loaded module.prop');
        } else {
            console.error('Failed to read module.prop:', result.stderr);
            updateText('prop-name', 'NeoZygisk (Load Failed)');
        }
    } catch (e) {
        console.error('Exec failed:', e);
        updateText('prop-name', 'NeoZygisk (Error)');
    }
}

function parseModuleProp(text) {
    const lines = text.split('\n');
    const data = {};
    const kvRegex = /^([^=]+)=(.*)$/;

    lines.forEach(line => {
        line = line.trim();
        if (!line) return;
        if (kvRegex.test(line)) {
            const match = line.match(kvRegex);
            data[match[1].trim()] = match[2].trim();
        }
    });

    // Update Basic Info
    updateText('prop-name', data['name']);
    updateText('prop-version', data['version']);
    updateText('prop-author', data['author']);
    updateText('val-root', data['root_implementation']);

    // Update Device Info
    updateText('device-kernel', data['device_kernel']);
    updateText('device-sdk', data['device_sdk']);
    updateText('device-abi', data['device_abi']);

    // Update Statuses with Badges
    updateStatusBadge('val-monitor', data['monitor_status']);
    updateStatusBadge('val-zygote64', data['zygote_64_status']);
    updateStatusBadge('val-daemon64', data['daemon_64_status']);

    // Modules
    if (data['modules_count']) {
        const modulesCount = document.getElementById('val-modules-count');
        if (modulesCount) modulesCount.textContent = data['modules_count'];
    }

    if (data['modules_list']) {
        const modulesList = document.getElementById('modules-list');
        if (modulesList) {
            modulesList.innerHTML = '';
            const modules = data['modules_list'].split(',');
            modules.forEach(module => {
                if (module.trim()) {
                    const li = document.createElement('li');
                    li.textContent = module.trim();
                    modulesList.appendChild(li);
                }
            });
        }
    }
}

function updateText(id, value) {
    if (value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }
}

function updateStatusBadge(elementId, statusKey) {
    if (!statusKey) return;

    const el = document.getElementById(elementId);
    if (!el) return;

    // Get translated text
    const text = translations[currentLang][statusKey] || statusKey;
    el.textContent = text;

    // Icons
    const ICON_CHECK = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
    const ICON_X = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
    const ICON_UNKNOWN = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

    // Update badge color and icon
    const badge = el.parentElement;
    if (badge && badge.classList.contains('badge')) {
        // Store status for potential re-translation
        badge.setAttribute('data-status', statusKey);

        badge.classList.remove('green', 'red', 'gray');

        // Find existing SVG to replace, or prepend if missing (though HTML has it)
        let svg = badge.querySelector('svg');
        if (!svg) {
            // Create a placeholder if missing, though it should be there
            const temp = document.createElement('span');
            badge.insertBefore(temp, badge.firstChild);
            svg = temp;
        }

        if (['running', 'injected', 'tracing'].includes(statusKey)) {
            badge.classList.add('green');
            if (svg.outerHTML !== ICON_CHECK) svg.outerHTML = ICON_CHECK;
        } else if (['crashed', 'not_injected', 'stopped', 'exited'].includes(statusKey)) {
            badge.classList.add('red');
            if (svg.outerHTML !== ICON_X) svg.outerHTML = ICON_X;
        } else {
            // unknown and others
            badge.classList.add('gray');
            if (svg.outerHTML !== ICON_UNKNOWN) svg.outerHTML = ICON_UNKNOWN;
        }
    }
}
