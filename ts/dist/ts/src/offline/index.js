// Offline module exports
export { PowerManageDB, getDB, isIndexedDBAvailable, } from './db.js';
export { SyncQueue, getSyncQueue, } from './sync.js';
export { cacheDevices, getCachedDevices, getCachedDevice, cacheDeviceActions, getCachedDeviceActions, getCachedAvailableActions, isCacheStale, refreshCacheIfStale, } from './cache.js';
/**
 * Online/offline status tracking.
 */
export class OnlineStatus {
    listeners = new Set();
    _isOnline;
    constructor() {
        this._isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;
        if (typeof window !== 'undefined') {
            window.addEventListener('online', () => this.setOnline(true));
            window.addEventListener('offline', () => this.setOnline(false));
        }
    }
    get isOnline() {
        return this._isOnline;
    }
    setOnline(online) {
        if (this._isOnline !== online) {
            this._isOnline = online;
            this.notify();
        }
    }
    subscribe(listener) {
        this.listeners.add(listener);
        listener(this._isOnline);
        return () => this.listeners.delete(listener);
    }
    notify() {
        this.listeners.forEach((listener) => listener(this._isOnline));
    }
}
let onlineStatus = null;
export function getOnlineStatus() {
    if (!onlineStatus) {
        onlineStatus = new OnlineStatus();
    }
    return onlineStatus;
}
//# sourceMappingURL=index.js.map