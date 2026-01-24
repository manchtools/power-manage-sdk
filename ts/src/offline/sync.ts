// Sync queue for offline changes

import { getDB, type PendingChange } from './db.js';
import { getClient, type PowerManageClient } from '../client.js';

export interface SyncResult {
  success: boolean;
  processed: number;
  failed: number;
  errors: Array<{ id: number; error: string }>;
}

type SyncListener = (result: SyncResult | null, pending: number) => void;

/**
 * SyncQueue manages pending changes and syncs them when online.
 */
export class SyncQueue {
  private listeners: Set<SyncListener> = new Set();
  private isSyncing = false;

  /**
   * Queue a change to be synced later.
   */
  async queueChange(
    type: PendingChange['type'],
    payload: unknown
  ): Promise<number> {
    const db = getDB();
    const id = await db.pendingChanges.add({
      type,
      payload: JSON.stringify(payload),
      createdAt: new Date(),
      retryCount: 0,
    });

    this.notifyListeners(null);
    return id as number;
  }

  /**
   * Get all pending changes.
   */
  async getPendingChanges(): Promise<PendingChange[]> {
    const db = getDB();
    return db.pendingChanges.orderBy('createdAt').toArray();
  }

  /**
   * Get pending change count.
   */
  async getPendingCount(): Promise<number> {
    const db = getDB();
    return db.pendingChanges.count();
  }

  /**
   * Sync all pending changes.
   */
  async sync(client?: PowerManageClient): Promise<SyncResult> {
    if (this.isSyncing) {
      return { success: false, processed: 0, failed: 0, errors: [] };
    }

    this.isSyncing = true;
    const db = getDB();
    const apiClient = client || getClient();

    const result: SyncResult = {
      success: true,
      processed: 0,
      failed: 0,
      errors: [],
    };

    try {
      const pending = await this.getPendingChanges();

      for (const change of pending) {
        try {
          await this.processChange(change, apiClient);
          await db.pendingChanges.delete(change.id!);
          result.processed++;
        } catch (err) {
          result.failed++;
          result.errors.push({
            id: change.id!,
            error: err instanceof Error ? err.message : String(err),
          });

          // Update retry count
          await db.pendingChanges.update(change.id!, {
            retryCount: change.retryCount + 1,
            lastError: err instanceof Error ? err.message : String(err),
          });
        }
      }

      result.success = result.failed === 0;
    } finally {
      this.isSyncing = false;
      this.notifyListeners(result);
    }

    return result;
  }

  /**
   * Remove a specific pending change.
   */
  async removeChange(id: number): Promise<void> {
    const db = getDB();
    await db.pendingChanges.delete(id);
    this.notifyListeners(null);
  }

  /**
   * Clear all pending changes.
   */
  async clearAll(): Promise<void> {
    const db = getDB();
    await db.pendingChanges.clear();
    this.notifyListeners(null);
  }

  /**
   * Subscribe to sync events.
   */
  subscribe(listener: SyncListener): () => void {
    this.listeners.add(listener);
    // Notify with current state
    this.getPendingCount().then((count) => {
      listener(null, count);
    });
    return () => this.listeners.delete(listener);
  }

  private async processChange(
    change: PendingChange,
    client: PowerManageClient
  ): Promise<void> {
    const payload = JSON.parse(change.payload);

    switch (change.type) {
      case 'trigger_action':
        // Trigger an action on a device
        // This would call the appropriate API endpoint
        // For now, we'll implement this when the action trigger API is available
        console.log('Would trigger action:', payload);
        break;

      case 'update_device':
        // Update device metadata
        await client.devices.updateDevice(payload);
        break;

      case 'create_assignment':
        // Create a new assignment
        await client.assignments.createAssignment(payload);
        break;

      default:
        throw new Error(`Unknown change type: ${change.type}`);
    }
  }

  private async notifyListeners(result: SyncResult | null): Promise<void> {
    const count = await this.getPendingCount();
    this.listeners.forEach((listener) => listener(result, count));
  }
}

// Singleton instance
let syncQueue: SyncQueue | null = null;

/**
 * Get the global SyncQueue instance.
 */
export function getSyncQueue(): SyncQueue {
  if (!syncQueue) {
    syncQueue = new SyncQueue();
  }
  return syncQueue;
}
