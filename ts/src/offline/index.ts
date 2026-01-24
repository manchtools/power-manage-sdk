// Offline module exports
export {
  PowerManageDB,
  getDB,
  isIndexedDBAvailable,
  type CachedDevice,
  type CachedAction,
  type PendingChange,
  type SyncStatus,
} from './db.js';

export {
  SyncQueue,
  getSyncQueue,
  type SyncResult,
} from './sync.js';

export {
  cacheDevices,
  getCachedDevices,
  getCachedDevice,
  cacheDeviceActions,
  getCachedDeviceActions,
  getCachedAvailableActions,
  isCacheStale,
  refreshCacheIfStale,
} from './cache.js';

/**
 * Online/offline status tracking.
 */
export class OnlineStatus {
  private listeners: Set<(online: boolean) => void> = new Set();
  private _isOnline: boolean;

  constructor() {
    this._isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;

    if (typeof window !== 'undefined') {
      window.addEventListener('online', () => this.setOnline(true));
      window.addEventListener('offline', () => this.setOnline(false));
    }
  }

  get isOnline(): boolean {
    return this._isOnline;
  }

  private setOnline(online: boolean): void {
    if (this._isOnline !== online) {
      this._isOnline = online;
      this.notify();
    }
  }

  subscribe(listener: (online: boolean) => void): () => void {
    this.listeners.add(listener);
    listener(this._isOnline);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    this.listeners.forEach((listener) => listener(this._isOnline));
  }
}

let onlineStatus: OnlineStatus | null = null;

export function getOnlineStatus(): OnlineStatus {
  if (!onlineStatus) {
    onlineStatus = new OnlineStatus();
  }
  return onlineStatus;
}
