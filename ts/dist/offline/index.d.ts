export { PowerManageDB, getDB, isIndexedDBAvailable, type CachedDevice, type CachedAction, type PendingChange, type SyncStatus, } from './db.js';
export { SyncQueue, getSyncQueue, type SyncResult, } from './sync.js';
export { cacheDevices, getCachedDevices, getCachedDevice, cacheDeviceActions, getCachedDeviceActions, getCachedAvailableActions, isCacheStale, refreshCacheIfStale, } from './cache.js';
/**
 * Online/offline status tracking.
 */
export declare class OnlineStatus {
    private listeners;
    private _isOnline;
    constructor();
    get isOnline(): boolean;
    private setOnline;
    subscribe(listener: (online: boolean) => void): () => void;
    private notify;
}
export declare function getOnlineStatus(): OnlineStatus;
//# sourceMappingURL=index.d.ts.map