// IndexedDB schema using Dexie.js for offline support

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
  state: string; // 'required', 'available', 'absent'
  cachedAt: Date;
}

/**
 * Pending change to be synced when online.
 */
export interface PendingChange {
  id?: number;
  type: 'trigger_action' | 'update_device' | 'create_assignment';
  payload: string; // JSON stringified payload
  createdAt: Date;
  retryCount: number;
  lastError?: string;
}

/**
 * Sync status tracking.
 */
export interface SyncStatus {
  id: string; // 'main' for singleton
  lastSyncAt: Date | null;
  pendingCount: number;
  isOnline: boolean;
}

/**
 * Power Manage IndexedDB database.
 */
export class PowerManageDB extends Dexie {
  devices!: Table<CachedDevice, string>;
  actions!: Table<CachedAction, string>;
  pendingChanges!: Table<PendingChange, number>;
  syncStatus!: Table<SyncStatus, string>;

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
  async clearCache(): Promise<void> {
    await Promise.all([
      this.devices.clear(),
      this.actions.clear(),
    ]);
  }

  /**
   * Clear pending changes.
   */
  async clearPendingChanges(): Promise<void> {
    await this.pendingChanges.clear();
  }

  /**
   * Get pending change count.
   */
  async getPendingCount(): Promise<number> {
    return this.pendingChanges.count();
  }
}

// Singleton instance
let db: PowerManageDB | null = null;

/**
 * Get the database instance.
 */
export function getDB(): PowerManageDB {
  if (!db) {
    db = new PowerManageDB();
  }
  return db;
}

/**
 * Check if IndexedDB is available.
 */
export function isIndexedDBAvailable(): boolean {
  try {
    return typeof indexedDB !== 'undefined';
  } catch {
    return false;
  }
}
