// IndexedDB schema using Dexie.js for offline support
import Dexie from 'dexie';
/**
 * Power Manage IndexedDB database.
 */
export class PowerManageDB extends Dexie {
    devices;
    actions;
    pendingChanges;
    syncStatus;
    constructor() {
        super('power-manage');
        this.version(1).stores({
            devices: 'id, hostname, status, cachedAt',
            actions: 'id, deviceId, state, cachedAt',
            pendingChanges: '++id, type, createdAt',
            syncStatus: 'id',
        });
    }
    /**
     * Clear all cached data.
     */
    async clearCache() {
        await Promise.all([
            this.devices.clear(),
            this.actions.clear(),
        ]);
    }
    /**
     * Clear pending changes.
     */
    async clearPendingChanges() {
        await this.pendingChanges.clear();
    }
    /**
     * Get pending change count.
     */
    async getPendingCount() {
        return this.pendingChanges.count();
    }
}
// Singleton instance
let db = null;
/**
 * Get the database instance.
 */
export function getDB() {
    if (!db) {
        db = new PowerManageDB();
    }
    return db;
}
/**
 * Check if IndexedDB is available.
 */
export function isIndexedDBAvailable() {
    try {
        return typeof indexedDB !== 'undefined';
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=db.js.map