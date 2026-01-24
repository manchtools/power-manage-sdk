// Auth store for managing authentication state with localStorage persistence
const STORAGE_KEY = 'pm_auth';
/**
 * AuthStore manages authentication state with localStorage persistence.
 * Framework-agnostic: use subscribe() for reactive updates.
 */
export class AuthStore {
    state;
    listeners = new Set();
    constructor() {
        this.state = this.loadFromStorage();
    }
    /**
     * Get current authentication state.
     */
    getState() {
        return { ...this.state };
    }
    /**
     * Check if user is authenticated.
     */
    isAuthenticated() {
        return this.state.isAuthenticated;
    }
    /**
     * Get current user or null.
     */
    getUser() {
        return this.state.user;
    }
    /**
     * Get session ID or null.
     */
    getSessionId() {
        return this.state.sessionId;
    }
    /**
     * Set session after successful login.
     */
    setSession(user, sessionId) {
        this.state = {
            isAuthenticated: true,
            user,
            sessionId,
        };
        this.persist();
        this.notify();
    }
    /**
     * Clear session (logout).
     */
    clearSession() {
        this.state = {
            isAuthenticated: false,
            user: null,
            sessionId: null,
        };
        localStorage.removeItem(STORAGE_KEY);
        this.notify();
    }
    /**
     * Subscribe to authentication state changes.
     * @returns Unsubscribe function.
     */
    subscribe(listener) {
        this.listeners.add(listener);
        // Immediately call with current state
        listener(this.getState());
        return () => this.listeners.delete(listener);
    }
    loadFromStorage() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                const parsed = JSON.parse(stored);
                // Validate the stored state has expected shape
                if (parsed.isAuthenticated && parsed.user && parsed.sessionId) {
                    return parsed;
                }
            }
        }
        catch {
            // Ignore parse errors
        }
        return {
            isAuthenticated: false,
            user: null,
            sessionId: null,
        };
    }
    persist() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
        }
        catch {
            // Ignore storage errors (e.g., private browsing)
        }
    }
    notify() {
        const state = this.getState();
        this.listeners.forEach((listener) => listener(state));
    }
}
// Singleton instance
let authStore = null;
/**
 * Get the global AuthStore instance.
 */
export function getAuthStore() {
    if (!authStore) {
        authStore = new AuthStore();
    }
    return authStore;
}
//# sourceMappingURL=store.js.map