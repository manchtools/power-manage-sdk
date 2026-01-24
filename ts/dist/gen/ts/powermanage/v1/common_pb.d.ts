import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
/**
 * Execution result status
 *
 * @generated from enum powermanage.v1.ExecutionStatus
 */
export declare enum ExecutionStatus {
    /**
     * @generated from enum value: EXECUTION_STATUS_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: EXECUTION_STATUS_SUCCESS = 1;
     */
    SUCCESS = 1,
    /**
     * @generated from enum value: EXECUTION_STATUS_FAILED = 2;
     */
    FAILED = 2,
    /**
     * No action needed, state already matches
     *
     * @generated from enum value: EXECUTION_STATUS_SKIPPED = 3;
     */
    SKIPPED = 3,
    /**
     * @generated from enum value: EXECUTION_STATUS_PENDING = 4;
     */
    PENDING = 4
}
/**
 * Log severity levels
 *
 * @generated from enum powermanage.v1.LogLevel
 */
export declare enum LogLevel {
    /**
     * @generated from enum value: LOG_LEVEL_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: LOG_LEVEL_DEBUG = 1;
     */
    DEBUG = 1,
    /**
     * @generated from enum value: LOG_LEVEL_INFO = 2;
     */
    INFO = 2,
    /**
     * @generated from enum value: LOG_LEVEL_WARN = 3;
     */
    WARN = 3,
    /**
     * @generated from enum value: LOG_LEVEL_ERROR = 4;
     */
    ERROR = 4
}
/**
 * Version comparison specifier
 *
 * @generated from enum powermanage.v1.VersionSpecifier
 */
export declare enum VersionSpecifier {
    /**
     * @generated from enum value: VERSION_SPECIFIER_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Must be exactly this version
     *
     * @generated from enum value: VERSION_SPECIFIER_EXACT = 1;
     */
    EXACT = 1,
    /**
     * Must be at least this version
     *
     * @generated from enum value: VERSION_SPECIFIER_MINIMUM = 2;
     */
    MINIMUM = 2,
    /**
     * Must be at most this version
     *
     * @generated from enum value: VERSION_SPECIFIER_MAXIMUM = 3;
     */
    MAXIMUM = 3
}
/**
 * Desired state for an action
 *
 * @generated from enum powermanage.v1.DesiredState
 */
export declare enum DesiredState {
    /**
     * @generated from enum value: DESIRED_STATE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: DESIRED_STATE_INSTALLED = 1;
     */
    INSTALLED = 1,
    /**
     * @generated from enum value: DESIRED_STATE_REMOVED = 2;
     */
    REMOVED = 2
}
/**
 * Unique identifier for an agent
 *
 * @generated from message powermanage.v1.AgentId
 */
export declare class AgentId extends Message<AgentId> {
    /**
     * UUID
     *
     * @generated from field: string id = 1;
     */
    id: string;
    constructor(data?: PartialMessage<AgentId>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AgentId";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AgentId;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AgentId;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AgentId;
    static equals(a: AgentId | PlainMessage<AgentId> | undefined, b: AgentId | PlainMessage<AgentId> | undefined): boolean;
}
/**
 * Unique identifier for an action instance
 *
 * @generated from message powermanage.v1.ActionId
 */
export declare class ActionId extends Message<ActionId> {
    /**
     * UUID
     *
     * @generated from field: string id = 1;
     */
    id: string;
    constructor(data?: PartialMessage<ActionId>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionId";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionId;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionId;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionId;
    static equals(a: ActionId | PlainMessage<ActionId> | undefined, b: ActionId | PlainMessage<ActionId> | undefined): boolean;
}
/**
 * Structured log entry
 *
 * @generated from message powermanage.v1.LogEntry
 */
export declare class LogEntry extends Message<LogEntry> {
    /**
     * UUID
     *
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: google.protobuf.Timestamp timestamp = 2;
     */
    timestamp?: Timestamp;
    /**
     * @generated from field: powermanage.v1.LogLevel level = 3;
     */
    level: LogLevel;
    /**
     * @generated from field: string message = 4;
     */
    message: string;
    /**
     * Associated action if applicable
     *
     * @generated from field: optional powermanage.v1.ActionId action_id = 5;
     */
    actionId?: ActionId;
    /**
     * Additional structured data
     *
     * @generated from field: map<string, string> metadata = 6;
     */
    metadata: {
        [key: string]: string;
    };
    constructor(data?: PartialMessage<LogEntry>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.LogEntry";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): LogEntry;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): LogEntry;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): LogEntry;
    static equals(a: LogEntry | PlainMessage<LogEntry> | undefined, b: LogEntry | PlainMessage<LogEntry> | undefined): boolean;
}
//# sourceMappingURL=common_pb.d.ts.map