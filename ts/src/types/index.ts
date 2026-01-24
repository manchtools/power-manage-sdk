// Re-export types from generated proto files
// Note: These are generated in sdk/gen/ts and need to be available

export type {
  User,
  Session,
  UserRole,
  WebAuthnCredential,
} from '../../../gen/ts/powermanage/v1/auth_pb.js';

export type {
  Device,
  DeviceStatus,
  RegistrationToken,
} from '../../../gen/ts/powermanage/v1/devices_pb.js';

export type {
  DeviceGroup,
  DeviceQuery,
} from '../../../gen/ts/powermanage/v1/device_groups_pb.js';

export type {
  ManagedAction,
  ActionSet,
  Definition,
  Assignment,
  EffectiveAction,
  AssignmentState,
  AssignmentSourceType,
  AssignmentTargetType,
} from '../../../gen/ts/powermanage/v1/action_management_pb.js';

export type {
  Action,
  ActionType,
  PackageActionParams,
} from '../../../gen/ts/powermanage/v1/actions_pb.js';

// Enums need to be exported as values too
export {
  UserRole as UserRoleEnum,
} from '../../../gen/ts/powermanage/v1/auth_pb.js';

export {
  DeviceStatus as DeviceStatusEnum,
} from '../../../gen/ts/powermanage/v1/devices_pb.js';

export {
  AssignmentState as AssignmentStateEnum,
  AssignmentSourceType as AssignmentSourceTypeEnum,
  AssignmentTargetType as AssignmentTargetTypeEnum,
} from '../../../gen/ts/powermanage/v1/action_management_pb.js';

export {
  ActionType as ActionTypeEnum,
} from '../../../gen/ts/powermanage/v1/actions_pb.js';
