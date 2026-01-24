// Cache management for offline data
import { getDB } from './db.js';
import { getClient } from '../client.js';
/**
 * Cache devices from server.
 */
export async function cacheDevices() {
    const client = getClient();
    const db = getDB();
    const response = await client.devices.listDevices({
        pageSize: 1000,
    });
    const cachedAt = new Date();
    const devices = response.devices.map((device) => ({
        id: device.id,
        hostname: device.hostname,
        displayName: device.displayName,
        osInfo: device.osInfo,
        status: device.status.toString(),
        labelsJson: JSON.stringify(device.labels),
        lastSeenAt: device.lastSeenAt?.toDate().toISOString() || '',
        cachedAt,
    }));
    // Clear old data and insert new
    await db.devices.clear();
    await db.devices.bulkPut(devices);
    return devices;
}
/**
 * Get cached devices.
 */
export async function getCachedDevices() {
    const db = getDB();
    return db.devices.toArray();
}
/**
 * Get cached device by ID.
 */
export async function getCachedDevice(id) {
    const db = getDB();
    return db.devices.get(id);
}
/**
 * Cache actions for a device.
 */
export async function cacheDeviceActions(deviceId) {
    const client = getClient();
    const db = getDB();
    const response = await client.assignments.getEffectiveActions({
        deviceId,
    });
    const cachedAt = new Date();
    const actions = response.effectiveActions.map((ea) => {
        // Extract params based on the oneof case
        let paramsJson = '{}';
        if (ea.action?.params.case === 'packageParams') {
            paramsJson = JSON.stringify(ea.action.params.value);
        }
        return {
            id: ea.action?.id?.id || '',
            deviceId,
            name: '', // Would need to fetch from managed action
            description: '',
            type: ea.action?.type.toString() || '',
            paramsJson,
            state: ea.state.toString(),
            cachedAt,
        };
    });
    // Clear old actions for this device and insert new
    await db.actions.where('deviceId').equals(deviceId).delete();
    await db.actions.bulkPut(actions);
    return actions;
}
/**
 * Get cached actions for a device.
 */
export async function getCachedDeviceActions(deviceId) {
    const db = getDB();
    return db.actions.where('deviceId').equals(deviceId).toArray();
}
/**
 * Get cached available actions for a device.
 */
export async function getCachedAvailableActions(deviceId) {
    const db = getDB();
    return db.actions
        .where(['deviceId', 'state'])
        .equals([deviceId, '2']) // ASSIGNMENT_STATE_AVAILABLE = 2
        .toArray();
}
/**
 * Check if cache is stale (older than maxAge).
 */
export async function isCacheStale(maxAgeMs = 5 * 60 * 1000) {
    const db = getDB();
    const device = await db.devices.orderBy('cachedAt').first();
    if (!device)
        return true;
    const age = Date.now() - device.cachedAt.getTime();
    return age > maxAgeMs;
}
/**
 * Refresh cache if stale.
 */
export async function refreshCacheIfStale(maxAgeMs) {
    const stale = await isCacheStale(maxAgeMs);
    if (stale) {
        try {
            await cacheDevices();
            return true;
        }
        catch {
            return false;
        }
    }
    return false;
}
//# sourceMappingURL=cache.js.map