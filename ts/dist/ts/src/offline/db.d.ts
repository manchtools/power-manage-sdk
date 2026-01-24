import Dexie, { type Table } from 'dexie';
/**
 * Cached device data.
 */
export interface CachedDevice {
    id: string;
    hostname: string;
    displayName: string;
    osInfo: string;
    status: string;
    labelsJson: string;
    lastSeenAt: string;
    cachedAt: Date;
}
/**
 * Cached action data for a device.
 */
export interface CachedAction {
    id: string;
    deviceId: string;
    name: string;
    description: string;
    type: string;
    paramsJson: string;
    state: string;
    cachedAt: Date;
}
/**
 * Pending change to be synced when online.
 */
export interface PendingChange {
    id?: number;
    type: 'trigger_action' | 'update_device' | 'create_assignment';
    payload: string;
    createdAt: Date;
    retryCount: number;
    lastError?: string;
}
/**
 * Sync status tracking.
 */
export interface SyncStatus {
    id: string;
    lastSyncAt: Date | null;
    pendingCount: number;
    isOnline: boolean;
}
/**
 * Power Manage IndexedDB database.
 */
export declare class PowerManageDB extends Dexie {
    devices: Table<CachedDevice, string>;
    actions: Table<CachedAction, string>;
    pendingChanges: Table<PendingChange, number>;
    syncStatus: Table<SyncStatus, string>;
    constructor();
    /**
     * Clear all cached data.
     */
    clearCache(): Promise<void>;
    /**
     * Clear pending changes.
     */
    clearPendingChanges(): Promise<void>;
    /**
     * Get pending change count.
     */
    getPendingCount(): Promise<number>;
}
/**
 * Get the database instance.
 */
export declare function getDB(): PowerManageDB;
/**
 * Check if IndexedDB is available.
 */
export declare function isIndexedDBAvailable(): boolean;
//# sourceMappingURL=db.d.ts.map