// Authentication store with automatic token refresh.
// Plain TypeScript — no framework dependencies.
// Refresh/logout functions are set lazily to avoid circular dependencies with ApiClient.

import type { User } from '../gen/ts/pm/v1/control_pb';
import superjson from 'superjson';

const AUTH_KEY = 'power-manage-auth';

export interface StoredAuth {
	accessToken: string | null;
	refreshToken: string | null;
	expiresAt: Date | null;
	user: User | null;
}

export interface RefreshResult {
	accessToken: string;
	refreshToken: string;
	expiresAt: Date;
}

function loadAuth(): StoredAuth {
	if (typeof sessionStorage === 'undefined') {
		return { accessToken: null, refreshToken: null, expiresAt: null, user: null };
	}
	const stored = sessionStorage.getItem(AUTH_KEY);
	if (stored) {
		try {
			return superjson.parse<StoredAuth>(stored);
		} catch {
			return { accessToken: null, refreshToken: null, expiresAt: null, user: null };
		}
	}
	return { accessToken: null, refreshToken: null, expiresAt: null, user: null };
}

function saveAuth(auth: StoredAuth) {
	if (typeof sessionStorage !== 'undefined') {
		sessionStorage.setItem(AUTH_KEY, superjson.stringify(auth));
	}
}

function clearAuth() {
	if (typeof sessionStorage !== 'undefined') {
		sessionStorage.removeItem(AUTH_KEY);
	}
}

export class AuthStore {
	private state: StoredAuth = loadAuth();
	private refreshPromise: Promise<void> | null = null;
	private refreshTimeoutId: ReturnType<typeof setTimeout> | null = null;
	private listeners = new Set<() => void>();

	private refreshFn: (() => Promise<RefreshResult | null>) | null = null;
	private logoutFn: (() => Promise<void>) | null = null;

	constructor() {
		if (typeof window !== 'undefined') {
			this.scheduleRefresh();
		}
	}

	private notify() {
		for (const fn of this.listeners) fn();
	}

	onChange(listener: () => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	setRefreshFn(fn: () => Promise<RefreshResult | null>) {
		this.refreshFn = fn;
	}

	setLogoutFn(fn: () => Promise<void>) {
		this.logoutFn = fn;
	}

	get user() {
		return this.state.user;
	}

	get accessToken() {
		return this.state.accessToken;
	}

	get refreshToken() {
		return this.state.refreshToken;
	}

	get isAuthenticated() {
		return this.state.user !== null && this.state.accessToken !== null && !this.isExpired();
	}

	get isAdmin() {
		return this.hasPermission('CreateRole');
	}

	hasPermission(permission: string) {
		const roles = this.state.user?.roles;
		if (!roles) return false;
		for (const role of roles) {
			if (role.permissions.includes(permission)) return true;
		}
		return false;
	}

	private isExpired() {
		if (!this.state.expiresAt) return true;
		return new Date() >= new Date(this.state.expiresAt.getTime() - 30000);
	}

	private scheduleRefresh() {
		if (this.refreshTimeoutId) {
			clearTimeout(this.refreshTimeoutId);
			this.refreshTimeoutId = null;
		}

		if (!this.state.expiresAt || !this.state.user) return;

		const refreshAt = this.state.expiresAt.getTime() - 60000;
		const delay = refreshAt - Date.now();

		if (delay > 0) {
			this.refreshTimeoutId = setTimeout(() => this.refresh(), delay);
		} else if (this.state.user) {
			this.refresh();
		}
	}

	setAuth(accessToken: string, refreshToken: string, expiresAt: Date, user: User) {
		this.state = { accessToken, refreshToken, expiresAt, user };
		saveAuth(this.state);
		this.scheduleRefresh();
		this.notify();
	}

	updateUser(user: User) {
		this.state.user = user;
		saveAuth(this.state);
		this.notify();
	}

	async refresh(): Promise<boolean> {
		if (!this.state.user || !this.state.refreshToken) return false;

		if (this.refreshPromise) {
			await this.refreshPromise;
			return this.isAuthenticated;
		}

		this.refreshPromise = this.doRefresh();
		try {
			await this.refreshPromise;
			return this.isAuthenticated;
		} finally {
			this.refreshPromise = null;
		}
	}

	private async doRefresh(): Promise<void> {
		if (!this.refreshFn) return;

		try {
			const result = await this.refreshFn();
			if (result) {
				this.state.accessToken = result.accessToken;
				this.state.refreshToken = result.refreshToken;
				this.state.expiresAt = result.expiresAt;
				saveAuth(this.state);
				this.scheduleRefresh();
				this.notify();
			}
		} catch (error) {
			console.error('Token refresh failed:', error);
		}
	}

	async ensureValidToken(): Promise<void> {
		if (this.isExpired() && this.state.user) {
			await this.refresh();
		}
	}

	async logout() {
		if (this.refreshTimeoutId) {
			clearTimeout(this.refreshTimeoutId);
			this.refreshTimeoutId = null;
		}

		if (this.state.user && this.logoutFn) {
			try {
				await this.logoutFn();
			} catch {
				// Ignore errors — we're logging out regardless
			}
		}

		this.state = { accessToken: null, refreshToken: null, expiresAt: null, user: null };
		clearAuth();
		this.notify();
	}
}
