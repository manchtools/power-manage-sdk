import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { ActionId, DesiredState, ExecutionStatus, VersionSpecifier } from "./common_pb.js";
/**
 * Action type enumeration
 *
 * @generated from enum powermanage.v1.ActionType
 */
export declare enum ActionType {
    /**
     * @generated from enum value: ACTION_TYPE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: ACTION_TYPE_APT = 1;
     */
    APT = 1,
    /**
     * Future action types will be added here
     *
     * @generated from enum value: ACTION_TYPE_DNF = 2;
     */
    DNF = 2
}
/**
 * Rollback policy for actions
 *
 * @generated from enum powermanage.v1.RollbackPolicy
 */
export declare enum RollbackPolicy {
    /**
     * Default: no automatic rollback
     *
     * @generated from enum value: ROLLBACK_POLICY_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Never rollback on failure
     *
     * @generated from enum value: ROLLBACK_POLICY_NONE = 1;
     */
    NONE = 1,
    /**
     * Rollback if action fails
     *
     * @generated from enum value: ROLLBACK_POLICY_ON_FAILURE = 2;
     */
    ON_FAILURE = 2,
    /**
     * Always rollback (useful for testing)
     *
     * @generated from enum value: ROLLBACK_POLICY_ALWAYS = 3;
     */
    ALWAYS = 3
}
/**
 * Package action parameters (used by APT and DNF)
 *
 * @generated from message powermanage.v1.PackageActionParams
 */
export declare class PackageActionParams extends Message<PackageActionParams> {
    /**
     * e.g., "nginx", "vim"
     *
     * @generated from field: string package_name = 1;
     */
    packageName: string;
    /**
     * e.g., "1.18.0", "latest"
     *
     * @generated from field: string version = 2;
     */
    version: string;
    /**
     * @generated from field: powermanage.v1.VersionSpecifier version_specifier = 3;
     */
    versionSpecifier: VersionSpecifier;
    /**
     * @generated from field: powermanage.v1.DesiredState desired_state = 4;
     */
    desiredState: DesiredState;
    /**
     * What to do on failure
     *
     * @generated from field: powermanage.v1.RollbackPolicy rollback_policy = 5;
     */
    rollbackPolicy: RollbackPolicy;
    constructor(data?: PartialMessage<PackageActionParams>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PackageActionParams";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PackageActionParams;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PackageActionParams;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PackageActionParams;
    static equals(a: PackageActionParams | PlainMessage<PackageActionParams> | undefined, b: PackageActionParams | PlainMessage<PackageActionParams> | undefined): boolean;
}
/**
 * Generic action definition
 *
 * @generated from message powermanage.v1.Action
 */
export declare class Action extends Message<Action> {
    /**
     * @generated from field: powermanage.v1.ActionId id = 1;
     */
    id?: ActionId;
    /**
     * @generated from field: powermanage.v1.ActionType type = 2;
     */
    type: ActionType;
    /**
     * Action-specific parameters (oneof for type safety)
     *
     * @generated from oneof powermanage.v1.Action.params
     */
    params: {
        /**
         * Future action params will be added here
         *
         * @generated from field: powermanage.v1.PackageActionParams package_params = 10;
         */
        value: PackageActionParams;
        case: "packageParams";
    } | {
        case: undefined;
        value?: undefined;
    };
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp updated_at = 21;
     */
    updatedAt?: Timestamp;
    constructor(data?: PartialMessage<Action>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Action";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Action;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Action;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Action;
    static equals(a: Action | PlainMessage<Action> | undefined, b: Action | PlainMessage<Action> | undefined): boolean;
}
/**
 * Current state of a package (as detected on the system)
 *
 * @generated from message powermanage.v1.PackageCurrentState
 */
export declare class PackageCurrentState extends Message<PackageCurrentState> {
    /**
     * @generated from field: bool is_installed = 1;
     */
    isInstalled: boolean;
    /**
     * Only set if installed
     *
     * @generated from field: optional string installed_version = 2;
     */
    installedVersion?: string;
    constructor(data?: PartialMessage<PackageCurrentState>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PackageCurrentState";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PackageCurrentState;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PackageCurrentState;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PackageCurrentState;
    static equals(a: PackageCurrentState | PlainMessage<PackageCurrentState> | undefined, b: PackageCurrentState | PlainMessage<PackageCurrentState> | undefined): boolean;
}
/**
 * Action state combining desired and current
 *
 * @generated from message powermanage.v1.ActionState
 */
export declare class ActionState extends Message<ActionState> {
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 1;
     */
    actionId?: ActionId;
    /**
     * @generated from field: powermanage.v1.ActionType type = 2;
     */
    type: ActionType;
    /**
     * Current state (oneof for type safety)
     *
     * @generated from oneof powermanage.v1.ActionState.current_state
     */
    currentState: {
        /**
         * @generated from field: powermanage.v1.PackageCurrentState package_state = 10;
         */
        value: PackageCurrentState;
        case: "packageState";
    } | {
        case: undefined;
        value?: undefined;
    };
    /**
     * Whether current matches desired
     *
     * @generated from field: bool in_desired_state = 20;
     */
    inDesiredState: boolean;
    /**
     * @generated from field: google.protobuf.Timestamp last_checked = 21;
     */
    lastChecked?: Timestamp;
    /**
     * @generated from field: optional google.protobuf.Timestamp last_executed = 22;
     */
    lastExecuted?: Timestamp;
    constructor(data?: PartialMessage<ActionState>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionState";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionState;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionState;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionState;
    static equals(a: ActionState | PlainMessage<ActionState> | undefined, b: ActionState | PlainMessage<ActionState> | undefined): boolean;
}
/**
 * Pre-execution snapshot for rollback support
 *
 * @generated from message powermanage.v1.PreExecutionSnapshot
 */
export declare class PreExecutionSnapshot extends Message<PreExecutionSnapshot> {
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 1;
     */
    actionId?: ActionId;
    /**
     * @generated from field: google.protobuf.Timestamp captured_at = 2;
     */
    capturedAt?: Timestamp;
    /**
     * Package-specific snapshot data
     *
     * @generated from oneof powermanage.v1.PreExecutionSnapshot.snapshot_data
     */
    snapshotData: {
        /**
         * @generated from field: powermanage.v1.PackageSnapshot package_snapshot = 10;
         */
        value: PackageSnapshot;
        case: "packageSnapshot";
    } | {
        case: undefined;
        value?: undefined;
    };
    constructor(data?: PartialMessage<PreExecutionSnapshot>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PreExecutionSnapshot";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PreExecutionSnapshot;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PreExecutionSnapshot;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PreExecutionSnapshot;
    static equals(a: PreExecutionSnapshot | PlainMessage<PreExecutionSnapshot> | undefined, b: PreExecutionSnapshot | PlainMessage<PreExecutionSnapshot> | undefined): boolean;
}
/**
 * Snapshot of package state before execution
 *
 * @generated from message powermanage.v1.PackageSnapshot
 */
export declare class PackageSnapshot extends Message<PackageSnapshot> {
    /**
     * @generated from field: string package_name = 1;
     */
    packageName: string;
    /**
     * @generated from field: bool was_installed = 2;
     */
    wasInstalled: boolean;
    /**
     * @generated from field: optional string installed_version = 3;
     */
    installedVersion?: string;
    /**
     * For DNF: the transaction ID before the action
     *
     * @generated from field: optional int64 dnf_transaction_id = 4;
     */
    dnfTransactionId?: bigint;
    constructor(data?: PartialMessage<PackageSnapshot>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PackageSnapshot";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PackageSnapshot;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PackageSnapshot;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PackageSnapshot;
    static equals(a: PackageSnapshot | PlainMessage<PackageSnapshot> | undefined, b: PackageSnapshot | PlainMessage<PackageSnapshot> | undefined): boolean;
}
/**
 * Result of a rollback attempt
 *
 * @generated from message powermanage.v1.RollbackResult
 */
export declare class RollbackResult extends Message<RollbackResult> {
    /**
     * Whether rollback was attempted
     *
     * @generated from field: bool attempted = 1;
     */
    attempted: boolean;
    /**
     * Whether rollback succeeded
     *
     * @generated from field: bool success = 2;
     */
    success: boolean;
    /**
     * @generated from field: optional string error_message = 3;
     */
    errorMessage?: string;
    /**
     * @generated from field: string stdout = 4;
     */
    stdout: string;
    /**
     * @generated from field: string stderr = 5;
     */
    stderr: string;
    /**
     * @generated from field: optional powermanage.v1.ActionState state_after_rollback = 6;
     */
    stateAfterRollback?: ActionState;
    constructor(data?: PartialMessage<RollbackResult>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RollbackResult";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RollbackResult;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RollbackResult;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RollbackResult;
    static equals(a: RollbackResult | PlainMessage<RollbackResult> | undefined, b: RollbackResult | PlainMessage<RollbackResult> | undefined): boolean;
}
/**
 * Result of executing an action
 *
 * @generated from message powermanage.v1.ActionResult
 */
export declare class ActionResult extends Message<ActionResult> {
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 1;
     */
    actionId?: ActionId;
    /**
     * @generated from field: powermanage.v1.ExecutionStatus status = 2;
     */
    status: ExecutionStatus;
    /**
     * @generated from field: optional string error_message = 3;
     */
    errorMessage?: string;
    /**
     * @generated from field: string stdout = 4;
     */
    stdout: string;
    /**
     * @generated from field: string stderr = 5;
     */
    stderr: string;
    /**
     * @generated from field: int64 duration_ms = 6;
     */
    durationMs: bigint;
    /**
     * @generated from field: google.protobuf.Timestamp executed_at = 7;
     */
    executedAt?: Timestamp;
    /**
     * @generated from field: optional powermanage.v1.ActionState state_after = 8;
     */
    stateAfter?: ActionState;
    /**
     * Rollback information
     *
     * @generated from field: optional powermanage.v1.PreExecutionSnapshot snapshot = 9;
     */
    snapshot?: PreExecutionSnapshot;
    /**
     * @generated from field: optional powermanage.v1.RollbackResult rollback = 10;
     */
    rollback?: RollbackResult;
    constructor(data?: PartialMessage<ActionResult>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionResult";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionResult;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionResult;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionResult;
    static equals(a: ActionResult | PlainMessage<ActionResult> | undefined, b: ActionResult | PlainMessage<ActionResult> | undefined): boolean;
}
//# sourceMappingURL=actions_pb.d.ts.map