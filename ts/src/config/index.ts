// Configuration store for server URL and app settings

const STORAGE_KEY = 'pm_config';

export interface AppConfig {
  serverUrl: string;
  configured?: boolean; // true after user completes setup (allows empty serverUrl for proxy)
  theme?: 'light' | 'dark' | 'system';
  locale?: string;
}

type ConfigListener = (config: AppConfig) => void;

/**
 * ConfigStore manages application configuration with localStorage persistence.
 * Framework-agnostic: use subscribe() for reactive updates.
 */
export class ConfigStore {
  private config: AppConfig;
  private listeners: Set<ConfigListener> = new Set();

  constructor() {
    this.config = this.loadFromStorage();
  }

  /**
   * Get current configuration.
   */
  getConfig(): AppConfig {
    return { ...this.config };
  }

  /**
   * Get the server URL.
   */
  getServerUrl(): string {
    return this.config.serverUrl;
  }

  /**
   * Check if setup has been completed.
   * Returns true if user went through setup (even with empty URL for proxy mode).
   */
  isConfigured(): boolean {
    return this.config.configured === true;
  }

  /**
   * Set the server URL and mark as configured.
   */
  setServerUrl(url: string): void {
    // Normalize URL (remove trailing slash)
    const normalized = url.replace(/\/+$/, '');
    this.config.serverUrl = normalized;
    this.config.configured = true;
    this.persist();
    this.notify();
  }

  /**
   * Set theme preference.
   */
  setTheme(theme: 'light' | 'dark' | 'system'): void {
    this.config.theme = theme;
    this.persist();
    this.notify();
  }

  /**
   * Set locale preference.
   */
  setLocale(locale: string): void {
    this.config.locale = locale;
    this.persist();
    this.notify();
  }

  /**
   * Update multiple config values at once.
   */
  update(partial: Partial<AppConfig>): void {
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
  clear(): void {
    this.config = { serverUrl: '', configured: false };
    localStorage.removeItem(STORAGE_KEY);
    this.notify();
  }

  /**
   * Subscribe to configuration changes.
   * @returns Unsubscribe function.
   */
  subscribe(listener: ConfigListener): () => void {
    this.listeners.add(listener);
    // Immediately call with current state
    listener(this.getConfig());
    return () => this.listeners.delete(listener);
  }

  private loadFromStorage(): AppConfig {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Ignore parse errors
    }
    return { serverUrl: '', configured: false };
  }

  private persist(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.config));
    } catch {
      // Ignore storage errors (e.g., private browsing)
    }
  }

  private notify(): void {
    const config = this.getConfig();
    this.listeners.forEach((listener) => listener(config));
  }
}

// Singleton instance
let configStore: ConfigStore | null = null;

/**
 * Get the global ConfigStore instance.
 */
export function getConfigStore(): ConfigStore {
  if (!configStore) {
    configStore = new ConfigStore();
  }
  return configStore;
}

/**
 * Parse server URL from query string if present.
 * Useful for deep linking: ?server=https://example.com
 */
export function getServerUrlFromQueryString(): string | null {
  if (typeof window === 'undefined') return null;

  const params = new URLSearchParams(window.location.search);
  return params.get('server');
}

/**
 * Initialize config from query string if not already configured.
 */
export function initConfigFromQueryString(): void {
  const store = getConfigStore();
  if (!store.isConfigured()) {
    const serverUrl = getServerUrlFromQueryString();
    if (serverUrl) {
      store.setServerUrl(serverUrl);
    }
  }
}
