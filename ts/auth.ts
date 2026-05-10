// Authentication store with automatic token refresh.
// Plain TypeScript — no framework dependencies.
// Refresh/logout functions are set lazily to avoid circular dependencies with ApiClient.

import type { User } from '../gen/ts/pm/v1/control_pb';
import superjson from 'superjson';

const AUTH_KEY = 'power-manage-auth';
const PERSIST_KEY = 'power-manage-persist';

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

const emptyAuth: StoredAuth = { accessToken: null, refreshToken: null, expiresAt: null, user: null };

function isPersistent(): boolean {
	if (typeof localStorage === 'undefined') return false;
	return localStorage.getItem(PERSIST_KEY) === 'true';
}

function loadAuth(): StoredAuth {
	if (typeof window === 'undefined') return { ...emptyAuth };

	// Honor the persist toggle when choosing read order. If the user
	// disabled "keep me signed in" we should not silently rehydrate from
	// localStorage on the next page load — that was the previous behavior
	// (F020 in the SDK tech-debt audit).
	const persistent = isPersistent();
	const primary = persistent ? localStorage.getItem(AUTH_KEY) : sessionStorage.getItem(AUTH_KEY);
	if (primary) {
		try { return superjson.parse<StoredAuth>(primary); } catch { /* ignore corrupt data */ }
	}

	const fallback = persistent ? sessionStorage.getItem(AUTH_KEY) : localStorage.getItem(AUTH_KEY);
	if (fallback) {
		try { return superjson.parse<StoredAuth>(fallback); } catch { /* ignore corrupt data */ }
	}

	return { ...emptyAuth };
}

function saveAuth(auth: StoredAuth) {
	if (typeof window === 'undefined') return;
	const data = superjson.stringify(auth);
	if (isPersistent()) {
		localStorage.setItem(AUTH_KEY, data);
	} else {
		sessionStorage.setItem(AUTH_KEY, data);
	}
}

function clearAuth() {
	if (typeof window === 'undefined') return;
	localStorage.removeItem(AUTH_KEY);
	sessionStorage.removeItem(AUTH_KEY);
	localStorage.removeItem(PERSIST_KEY);
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

	get persist(): boolean {
		return isPersistent();
	}

	setPersist(value: boolean) {
		if (typeof localStorage === 'undefined') return;
		if (value) {
			localStorage.setItem(PERSIST_KEY, 'true');
		} else {
			localStorage.removeItem(PERSIST_KEY);
			// Drop any previously-persisted token so the next page load
			// does not silently rehydrate from localStorage. F020.
			localStorage.removeItem(AUTH_KEY);
		}
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

	/**
	 * True if the user has the bootstrap admin role assigned (directly or
	 * via group inheritance). The previous implementation proxied the
	 * `CreateRole` permission, which any custom role could carry without
	 * being the admin — F019 in the SDK tech-debt audit. We now check the
	 * stable admin role ID (`00000000000000000000000001`, defined in
	 * server/internal/auth/reconcile.go AdminRoleID).
	 */
	get isAdmin() {
		const adminRoleID = '00000000000000000000000001';
		const directRoles = this.state.user?.roles ?? [];
		for (const role of directRoles) {
			if (role.id === adminRoleID) return true;
		}
		const inherited = this.state.user?.inheritedRoles ?? [];
		for (const ir of inherited) {
			if (ir.roleId === adminRoleID) return true;
		}
		return false;
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
