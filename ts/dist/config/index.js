// Configuration store for server URL and app settings
const STORAGE_KEY = 'pm_config';
/**
 * ConfigStore manages application configuration with localStorage persistence.
 * Framework-agnostic: use subscribe() for reactive updates.
 */
export class ConfigStore {
    config;
    listeners = new Set();
    constructor() {
        this.config = this.loadFromStorage();
    }
    /**
     * Get current configuration.
     */
    getConfig() {
        return { ...this.config };
    }
    /**
     * Get the server URL.
     */
    getServerUrl() {
        return this.config.serverUrl;
    }
    /**
     * Check if server URL is configured.
     */
    isConfigured() {
        return !!this.config.serverUrl;
    }
    /**
     * Set the server URL.
     */
    setServerUrl(url) {
        // Normalize URL (remove trailing slash)
        const normalized = url.replace(/\/+$/, '');
        this.config.serverUrl = normalized;
        this.persist();
        this.notify();
    }
    /**
     * Set theme preference.
     */
    setTheme(theme) {
        this.config.theme = theme;
        this.persist();
        this.notify();
    }
    /**
     * Set locale preference.
     */
    setLocale(locale) {
        this.config.locale = locale;
        this.persist();
        this.notify();
    }
    /**
     * Update multiple config values at once.
     */
    update(partial) {
        this.config = { ...this.config, ...partial };
        if (partial.serverUrl) {
            this.config.serverUrl = partial.serverUrl.replace(/\/+$/, '');
        }
        this.persist();
        this.notify();
    }
    /**
     * Clear all configuration.
     */
    clear() {
        this.config = { serverUrl: '' };
        localStorage.removeItem(STORAGE_KEY);
        this.notify();
    }
    /**
     * Subscribe to configuration changes.
     * @returns Unsubscribe function.
     */
    subscribe(listener) {
        this.listeners.add(listener);
        // Immediately call with current state
        listener(this.getConfig());
        return () => this.listeners.delete(listener);
    }
    loadFromStorage() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                return JSON.parse(stored);
            }
        }
        catch {
            // Ignore parse errors
        }
        return { serverUrl: '' };
    }
    persist() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(this.config));
        }
        catch {
            // Ignore storage errors (e.g., private browsing)
        }
    }
    notify() {
        const config = this.getConfig();
        this.listeners.forEach((listener) => listener(config));
    }
}
// Singleton instance
let configStore = null;
/**
 * Get the global ConfigStore instance.
 */
export function getConfigStore() {
    if (!configStore) {
        configStore = new ConfigStore();
    }
    return configStore;
}
/**
 * Parse server URL from query string if present.
 * Useful for deep linking: ?server=https://example.com
 */
export function getServerUrlFromQueryString() {
    if (typeof window === 'undefined')
        return null;
    const params = new URLSearchParams(window.location.search);
    return params.get('server');
}
/**
 * Initialize config from query string if not already configured.
 */
export function initConfigFromQueryString() {
    const store = getConfigStore();
    if (!store.isConfigured()) {
        const serverUrl = getServerUrlFromQueryString();
        if (serverUrl) {
            store.setServerUrl(serverUrl);
        }
    }
}
//# sourceMappingURL=index.js.map