import type { User } from '../types/index.js';
export interface AuthState {
    isAuthenticated: boolean;
    user: User | null;
    sessionId: string | null;
}
type AuthListener = (state: AuthState) => void;
/**
 * AuthStore manages authentication state with localStorage persistence.
 * Framework-agnostic: use subscribe() for reactive updates.
 */
export declare class AuthStore {
    private state;
    private listeners;
    constructor();
    /**
     * Get current authentication state.
     */
    getState(): AuthState;
    /**
     * Check if user is authenticated.
     */
    isAuthenticated(): boolean;
    /**
     * Get current user or null.
     */
    getUser(): User | null;
    /**
     * Get session ID or null.
     */
    getSessionId(): string | null;
    /**
     * Set session after successful login.
     */
    setSession(user: User, sessionId: string): void;
    /**
     * Clear session (logout).
     */
    clearSession(): void;
    /**
     * Subscribe to authentication state changes.
     * @returns Unsubscribe function.
     */
    subscribe(listener: AuthListener): () => void;
    private loadFromStorage;
    private persist;
    private notify;
}
/**
 * Get the global AuthStore instance.
 */
export declare function getAuthStore(): AuthStore;
export {};
//# sourceMappingURL=store.d.ts.map