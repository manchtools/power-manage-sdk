// Server configuration store with persistence.
// Plain TypeScript — no framework dependencies.

const CONFIG_KEY = 'power-manage-config';

export interface ServerConfig {
	serverUrl: string;
}

function loadConfig(): ServerConfig {
	if (typeof localStorage === 'undefined') {
		return { serverUrl: '' };
	}
	const stored = localStorage.getItem(CONFIG_KEY);
	if (stored) {
		try {
			return JSON.parse(stored);
		} catch {
			return { serverUrl: '' };
		}
	}
	return { serverUrl: '' };
}

function saveConfig(config: ServerConfig) {
	if (typeof localStorage !== 'undefined') {
		localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
	}
}

export class ConfigStore {
	private config: ServerConfig = loadConfig();
	private listeners = new Set<() => void>();

	private notify() {
		for (const fn of this.listeners) fn();
	}

	onChange(listener: () => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	get serverUrl() {
		return this.config.serverUrl;
	}

	set serverUrl(url: string) {
		this.config.serverUrl = url;
		saveConfig(this.config);
		this.notify();
	}

	get isConfigured() {
		return this.config.serverUrl.length > 0;
	}
}
