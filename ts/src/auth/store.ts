// Auth store for managing authentication state with localStorage persistence

import type { User } from '../types/index.js';

const STORAGE_KEY = 'pm_auth';

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
export class AuthStore {
  private state: AuthState;
  private listeners: Set<AuthListener> = new Set();

  constructor() {
    this.state = this.loadFromStorage();
  }

  /**
   * Get current authentication state.
   */
  getState(): AuthState {
    return { ...this.state };
  }

  /**
   * Check if user is authenticated.
   */
  isAuthenticated(): boolean {
    return this.state.isAuthenticated;
  }

  /**
   * Get current user or null.
   */
  getUser(): User | null {
    return this.state.user;
  }

  /**
   * Get session ID or null.
   */
  getSessionId(): string | null {
    return this.state.sessionId;
  }

  /**
   * Set session after successful login.
   */
  setSession(user: User, sessionId: string): void {
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
  clearSession(): void {
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
  subscribe(listener: AuthListener): () => void {
    this.listeners.add(listener);
    // Immediately call with current state
    listener(this.getState());
    return () => this.listeners.delete(listener);
  }

  private loadFromStorage(): AuthState {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Validate the stored state has expected shape
        if (parsed.isAuthenticated && parsed.user && parsed.sessionId) {
          return parsed;
        }
      }
    } catch {
      // Ignore parse errors
    }
    return {
      isAuthenticated: false,
      user: null,
      sessionId: null,
    };
  }

  private persist(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
    } catch {
      // Ignore storage errors (e.g., private browsing)
    }
  }

  private notify(): void {
    const state = this.getState();
    this.listeners.forEach((listener) => listener(state));
  }
}

// Singleton instance
let authStore: AuthStore | null = null;

/**
 * Get the global AuthStore instance.
 */
export function getAuthStore(): AuthStore {
  if (!authStore) {
    authStore = new AuthStore();
  }
  return authStore;
}
