export interface AppConfig {
    serverUrl: string;
    theme?: 'light' | 'dark' | 'system';
    locale?: string;
}
type ConfigListener = (config: AppConfig) => void;
/**
 * ConfigStore manages application configuration with localStorage persistence.
 * Framework-agnostic: use subscribe() for reactive updates.
 */
export declare class ConfigStore {
    private config;
    private listeners;
    constructor();
    /**
     * Get current configuration.
     */
    getConfig(): AppConfig;
    /**
     * Get the server URL.
     */
    getServerUrl(): string;
    /**
     * Check if server URL is configured.
     */
    isConfigured(): boolean;
    /**
     * Set the server URL.
     */
    setServerUrl(url: string): void;
    /**
     * Set theme preference.
     */
    setTheme(theme: 'light' | 'dark' | 'system'): void;
    /**
     * Set locale preference.
     */
    setLocale(locale: string): void;
    /**
     * Update multiple config values at once.
     */
    update(partial: Partial<AppConfig>): void;
    /**
     * Clear all configuration.
     */
    clear(): void;
    /**
     * Subscribe to configuration changes.
     * @returns Unsubscribe function.
     */
    subscribe(listener: ConfigListener): () => void;
    private loadFromStorage;
    private persist;
    private notify;
}
/**
 * Get the global ConfigStore instance.
 */
export declare function getConfigStore(): ConfigStore;
/**
 * Parse server URL from query string if present.
 * Useful for deep linking: ?server=https://example.com
 */
export declare function getServerUrlFromQueryString(): string | null;
/**
 * Initialize config from query string if not already configured.
 */
export declare function initConfigFromQueryString(): void;
export {};
//# sourceMappingURL=index.d.ts.map