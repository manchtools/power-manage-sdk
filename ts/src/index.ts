// Power Manage SDK
// Framework-agnostic TypeScript SDK for Power Manage

// Main client
export {
  PowerManageClient,
  getClient,
  resetClient,
  type PowerManageClientOptions,
} from './client.js';

// Config store
export {
  ConfigStore,
  getConfigStore,
  getServerUrlFromQueryString,
  initConfigFromQueryString,
  type AppConfig,
} from './config/index.js';

// Auth
export {
  AuthStore,
  getAuthStore,
  type AuthState,
  isWebAuthnAvailable,
  isPlatformAuthenticatorAvailable,
  isConditionalUIAvailable,
  createPasskey,
  authenticateWithPasskey,
} from './auth/index.js';

// Offline support
export {
  getDB,
  isIndexedDBAvailable,
  getSyncQueue,
  getOnlineStatus,
  cacheDevices,
  getCachedDevices,
  getCachedDevice,
  refreshCacheIfStale,
  type CachedDevice,
  type CachedAction,
  type PendingChange,
  type SyncResult,
} from './offline/index.js';

// Re-export types for convenience
export type {
  User,
  Session,
  Device,
  DeviceGroup,
  ManagedAction,
  ActionSet,
  Definition,
  Assignment,
  EffectiveAction,
} from './types/index.js';

export {
  UserRoleEnum,
  DeviceStatusEnum,
  AssignmentStateEnum,
  AssignmentSourceTypeEnum,
  AssignmentTargetTypeEnum,
  ActionTypeEnum,
} from './types/index.js';
