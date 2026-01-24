import { type PendingChange } from './db.js';
import { type PowerManageClient } from '../client.js';
export interface SyncResult {
    success: boolean;
    processed: number;
    failed: number;
    errors: Array<{
        id: number;
        error: string;
    }>;
}
type SyncListener = (result: SyncResult | null, pending: number) => void;
/**
 * SyncQueue manages pending changes and syncs them when online.
 */
export declare class SyncQueue {
    private listeners;
    private isSyncing;
    /**
     * Queue a change to be synced later.
     */
    queueChange(type: PendingChange['type'], payload: unknown): Promise<number>;
    /**
     * Get all pending changes.
     */
    getPendingChanges(): Promise<PendingChange[]>;
    /**
     * Get pending change count.
     */
    getPendingCount(): Promise<number>;
    /**
     * Sync all pending changes.
     */
    sync(client?: PowerManageClient): Promise<SyncResult>;
    /**
     * Remove a specific pending change.
     */
    removeChange(id: number): Promise<void>;
    /**
     * Clear all pending changes.
     */
    clearAll(): Promise<void>;
    /**
     * Subscribe to sync events.
     */
    subscribe(listener: SyncListener): () => void;
    private processChange;
    private notifyListeners;
}
/**
 * Get the global SyncQueue instance.
 */
export declare function getSyncQueue(): SyncQueue;
export {};
//# sourceMappingURL=sync.d.ts.map