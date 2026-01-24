import { type CachedDevice, type CachedAction } from './db.js';
/**
 * Cache devices from server.
 */
export declare function cacheDevices(): Promise<CachedDevice[]>;
/**
 * Get cached devices.
 */
export declare function getCachedDevices(): Promise<CachedDevice[]>;
/**
 * Get cached device by ID.
 */
export declare function getCachedDevice(id: string): Promise<CachedDevice | undefined>;
/**
 * Cache actions for a device.
 */
export declare function cacheDeviceActions(deviceId: string): Promise<CachedAction[]>;
/**
 * Get cached actions for a device.
 */
export declare function getCachedDeviceActions(deviceId: string): Promise<CachedAction[]>;
/**
 * Get cached available actions for a device.
 */
export declare function getCachedAvailableActions(deviceId: string): Promise<CachedAction[]>;
/**
 * Check if cache is stale (older than maxAge).
 */
export declare function isCacheStale(maxAgeMs?: number): Promise<boolean>;
/**
 * Refresh cache if stale.
 */
export declare function refreshCacheIfStale(maxAgeMs?: number): Promise<boolean>;
//# sourceMappingURL=cache.d.ts.map