// Power Manage TypeScript SDK
// Plain TypeScript — no framework dependencies.

import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { timestampDate } from '@bufbuild/protobuf/wkt';

export { ApiClient, type ClientOptions } from './client';
export type {
	User, Device, RegistrationToken, ManagedAction, ActionSet, Definition,
	DeviceGroup, Assignment, ActionExecution, AuditEvent, InventoryTableResult,
	Role, PermissionInfo, UserGroup, UserGroupMember, IdentityProvider, IdentityLink,
	LpsPassword, LuksKey, CreateActionRequest, UpdateActionParamsRequest
} from './client';
export { AuthStore, type StoredAuth, type RefreshResult } from './auth';
export { ConfigStore, type ServerConfig } from './config';
export { OfflineStore, type DraftType } from './offline';

// Re-export generated types
export * from '../gen/ts/pm/v1/control_pb';
export * from '../gen/ts/pm/v1/actions_pb';
export * from '../gen/ts/pm/v1/common_pb';

// Helper to format protobuf Timestamp to a localized date string
export function formatTimestamp(timestamp: Timestamp | undefined): string {
	if (!timestamp) return 'Never';
	return timestampDate(timestamp).toLocaleDateString();
}

// Helper to format protobuf Timestamp to a localized date-time string
export function formatTimestampDateTime(timestamp: Timestamp | undefined): string {
	if (!timestamp) return 'Never';
	return timestampDate(timestamp).toLocaleString();
}
