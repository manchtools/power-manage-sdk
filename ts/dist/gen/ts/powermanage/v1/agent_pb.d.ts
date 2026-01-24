import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { Action, ActionResult, ActionState } from "./actions_pb.js";
import { ActionId, AgentId, LogEntry } from "./common_pb.js";
/**
 * @generated from message powermanage.v1.AgentMessage
 */
export declare class AgentMessage extends Message<AgentMessage> {
    /**
     * Correlation ID for request-response matching
     *
     * @generated from field: string correlation_id = 1;
     */
    correlationId: string;
    /**
     * @generated from oneof powermanage.v1.AgentMessage.payload
     */
    payload: {
        /**
         * Initial handshake when stream opens
         *
         * @generated from field: powermanage.v1.AgentHandshake handshake = 10;
         */
        value: AgentHandshake;
        case: "handshake";
    } | {
        /**
         * Heartbeat/keepalive
         *
         * @generated from field: powermanage.v1.AgentHeartbeat heartbeat = 11;
         */
        value: AgentHeartbeat;
        case: "heartbeat";
    } | {
        /**
         * Action execution result
         *
         * @generated from field: powermanage.v1.ActionResult action_result = 12;
         */
        value: ActionResult;
        case: "actionResult";
    } | {
        /**
         * Batch of log entries
         *
         * @generated from field: powermanage.v1.LogBatch log_batch = 13;
         */
        value: LogBatch;
        case: "logBatch";
    } | {
        /**
         * Current state report (periodic or on-demand)
         *
         * @generated from field: powermanage.v1.StateReport state_report = 14;
         */
        value: StateReport;
        case: "stateReport";
    } | {
        /**
         * Acknowledgment of received server message
         *
         * @generated from field: powermanage.v1.Acknowledgment ack = 15;
         */
        value: Acknowledgment;
        case: "ack";
    } | {
        case: undefined;
        value?: undefined;
    };
    constructor(data?: PartialMessage<AgentMessage>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AgentMessage";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AgentMessage;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AgentMessage;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AgentMessage;
    static equals(a: AgentMessage | PlainMessage<AgentMessage> | undefined, b: AgentMessage | PlainMessage<AgentMessage> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AgentHandshake
 */
export declare class AgentHandshake extends Message<AgentHandshake> {
    /**
     * @generated from field: powermanage.v1.AgentId agent_id = 1;
     */
    agentId?: AgentId;
    /**
     * @generated from field: string agent_version = 2;
     */
    agentVersion: string;
    /**
     * @generated from field: string hostname = 3;
     */
    hostname: string;
    /**
     * e.g., "Ubuntu 22.04", "Fedora 39"
     *
     * @generated from field: string os_info = 4;
     */
    osInfo: string;
    /**
     * @generated from field: google.protobuf.Timestamp boot_time = 5;
     */
    bootTime?: Timestamp;
    constructor(data?: PartialMessage<AgentHandshake>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AgentHandshake";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AgentHandshake;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AgentHandshake;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AgentHandshake;
    static equals(a: AgentHandshake | PlainMessage<AgentHandshake> | undefined, b: AgentHandshake | PlainMessage<AgentHandshake> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AgentHeartbeat
 */
export declare class AgentHeartbeat extends Message<AgentHeartbeat> {
    /**
     * @generated from field: google.protobuf.Timestamp timestamp = 1;
     */
    timestamp?: Timestamp;
    /**
     * @generated from field: uint64 uptime_seconds = 2;
     */
    uptimeSeconds: bigint;
    /**
     * @generated from field: uint32 pending_actions = 3;
     */
    pendingActions: number;
    /**
     * @generated from field: uint32 pending_logs = 4;
     */
    pendingLogs: number;
    constructor(data?: PartialMessage<AgentHeartbeat>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AgentHeartbeat";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AgentHeartbeat;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AgentHeartbeat;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AgentHeartbeat;
    static equals(a: AgentHeartbeat | PlainMessage<AgentHeartbeat> | undefined, b: AgentHeartbeat | PlainMessage<AgentHeartbeat> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.LogBatch
 */
export declare class LogBatch extends Message<LogBatch> {
    /**
     * @generated from field: repeated powermanage.v1.LogEntry entries = 1;
     */
    entries: LogEntry[];
    constructor(data?: PartialMessage<LogBatch>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.LogBatch";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): LogBatch;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): LogBatch;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): LogBatch;
    static equals(a: LogBatch | PlainMessage<LogBatch> | undefined, b: LogBatch | PlainMessage<LogBatch> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.StateReport
 */
export declare class StateReport extends Message<StateReport> {
    /**
     * @generated from field: repeated powermanage.v1.ActionState action_states = 1;
     */
    actionStates: ActionState[];
    /**
     * @generated from field: google.protobuf.Timestamp reported_at = 2;
     */
    reportedAt?: Timestamp;
    /**
     * True if from 30-min periodic check
     *
     * @generated from field: bool is_reconciliation_run = 3;
     */
    isReconciliationRun: boolean;
    constructor(data?: PartialMessage<StateReport>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.StateReport";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): StateReport;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): StateReport;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): StateReport;
    static equals(a: StateReport | PlainMessage<StateReport> | undefined, b: StateReport | PlainMessage<StateReport> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.Acknowledgment
 */
export declare class Acknowledgment extends Message<Acknowledgment> {
    /**
     * @generated from field: string message_id = 1;
     */
    messageId: string;
    /**
     * @generated from field: bool success = 2;
     */
    success: boolean;
    /**
     * @generated from field: optional string error = 3;
     */
    error?: string;
    constructor(data?: PartialMessage<Acknowledgment>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Acknowledgment";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Acknowledgment;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Acknowledgment;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Acknowledgment;
    static equals(a: Acknowledgment | PlainMessage<Acknowledgment> | undefined, b: Acknowledgment | PlainMessage<Acknowledgment> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ServerMessage
 */
export declare class ServerMessage extends Message<ServerMessage> {
    /**
     * Message ID for acknowledgment
     *
     * @generated from field: string message_id = 1;
     */
    messageId: string;
    /**
     * @generated from oneof powermanage.v1.ServerMessage.payload
     */
    payload: {
        /**
         * Response to handshake
         *
         * @generated from field: powermanage.v1.ServerHandshakeResponse handshake_response = 10;
         */
        value: ServerHandshakeResponse;
        case: "handshakeResponse";
    } | {
        /**
         * Heartbeat response
         *
         * @generated from field: powermanage.v1.ServerHeartbeatResponse heartbeat_response = 11;
         */
        value: ServerHeartbeatResponse;
        case: "heartbeatResponse";
    } | {
        /**
         * Push new or updated action
         *
         * @generated from field: powermanage.v1.ActionPush action_push = 12;
         */
        value: ActionPush;
        case: "actionPush";
    } | {
        /**
         * Remove an action
         *
         * @generated from field: powermanage.v1.ActionRemove action_remove = 13;
         */
        value: ActionRemove;
        case: "actionRemove";
    } | {
        /**
         * Request immediate state check
         *
         * @generated from field: powermanage.v1.StateCheckRequest state_check_request = 14;
         */
        value: StateCheckRequest;
        case: "stateCheckRequest";
    } | {
        /**
         * Request immediate reconciliation
         *
         * @generated from field: powermanage.v1.ReconcileRequest reconcile_request = 15;
         */
        value: ReconcileRequest;
        case: "reconcileRequest";
    } | {
        /**
         * Batch of actions (initial sync or bulk update)
         *
         * @generated from field: powermanage.v1.ActionBatch action_batch = 16;
         */
        value: ActionBatch;
        case: "actionBatch";
    } | {
        case: undefined;
        value?: undefined;
    };
    constructor(data?: PartialMessage<ServerMessage>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ServerMessage";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ServerMessage;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ServerMessage;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ServerMessage;
    static equals(a: ServerMessage | PlainMessage<ServerMessage> | undefined, b: ServerMessage | PlainMessage<ServerMessage> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ServerHandshakeResponse
 */
export declare class ServerHandshakeResponse extends Message<ServerHandshakeResponse> {
    /**
     * @generated from field: bool accepted = 1;
     */
    accepted: boolean;
    /**
     * @generated from field: optional string rejection_reason = 2;
     */
    rejectionReason?: string;
    /**
     * @generated from field: google.protobuf.Timestamp server_time = 3;
     */
    serverTime?: Timestamp;
    /**
     * Server can override default
     *
     * @generated from field: uint32 reconciliation_interval_seconds = 4;
     */
    reconciliationIntervalSeconds: number;
    constructor(data?: PartialMessage<ServerHandshakeResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ServerHandshakeResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ServerHandshakeResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ServerHandshakeResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ServerHandshakeResponse;
    static equals(a: ServerHandshakeResponse | PlainMessage<ServerHandshakeResponse> | undefined, b: ServerHandshakeResponse | PlainMessage<ServerHandshakeResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ServerHeartbeatResponse
 */
export declare class ServerHeartbeatResponse extends Message<ServerHeartbeatResponse> {
    /**
     * @generated from field: google.protobuf.Timestamp server_time = 1;
     */
    serverTime?: Timestamp;
    constructor(data?: PartialMessage<ServerHeartbeatResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ServerHeartbeatResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ServerHeartbeatResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ServerHeartbeatResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ServerHeartbeatResponse;
    static equals(a: ServerHeartbeatResponse | PlainMessage<ServerHeartbeatResponse> | undefined, b: ServerHeartbeatResponse | PlainMessage<ServerHeartbeatResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ActionPush
 */
export declare class ActionPush extends Message<ActionPush> {
    /**
     * @generated from field: powermanage.v1.Action action = 1;
     */
    action?: Action;
    /**
     * If true, don't wait for reconciliation
     *
     * @generated from field: bool execute_immediately = 2;
     */
    executeImmediately: boolean;
    constructor(data?: PartialMessage<ActionPush>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionPush";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionPush;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionPush;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionPush;
    static equals(a: ActionPush | PlainMessage<ActionPush> | undefined, b: ActionPush | PlainMessage<ActionPush> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ActionRemove
 */
export declare class ActionRemove extends Message<ActionRemove> {
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 1;
     */
    actionId?: ActionId;
    constructor(data?: PartialMessage<ActionRemove>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionRemove";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionRemove;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionRemove;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionRemove;
    static equals(a: ActionRemove | PlainMessage<ActionRemove> | undefined, b: ActionRemove | PlainMessage<ActionRemove> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.StateCheckRequest
 */
export declare class StateCheckRequest extends Message<StateCheckRequest> {
    /**
     * Empty means all actions
     *
     * @generated from field: repeated powermanage.v1.ActionId action_ids = 1;
     */
    actionIds: ActionId[];
    constructor(data?: PartialMessage<StateCheckRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.StateCheckRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): StateCheckRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): StateCheckRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): StateCheckRequest;
    static equals(a: StateCheckRequest | PlainMessage<StateCheckRequest> | undefined, b: StateCheckRequest | PlainMessage<StateCheckRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ReconcileRequest
 */
export declare class ReconcileRequest extends Message<ReconcileRequest> {
    /**
     * Empty means all actions
     *
     * @generated from field: repeated powermanage.v1.ActionId action_ids = 1;
     */
    actionIds: ActionId[];
    constructor(data?: PartialMessage<ReconcileRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ReconcileRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ReconcileRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ReconcileRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ReconcileRequest;
    static equals(a: ReconcileRequest | PlainMessage<ReconcileRequest> | undefined, b: ReconcileRequest | PlainMessage<ReconcileRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ActionBatch
 */
export declare class ActionBatch extends Message<ActionBatch> {
    /**
     * @generated from field: repeated powermanage.v1.Action actions = 1;
     */
    actions: Action[];
    /**
     * If true, replace entire action set
     *
     * @generated from field: bool replace_all = 2;
     */
    replaceAll: boolean;
    constructor(data?: PartialMessage<ActionBatch>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionBatch";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionBatch;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionBatch;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionBatch;
    static equals(a: ActionBatch | PlainMessage<ActionBatch> | undefined, b: ActionBatch | PlainMessage<ActionBatch> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RegisterRequest
 */
export declare class RegisterRequest extends Message<RegisterRequest> {
    /**
     * One-time token from admin/web GUI
     *
     * @generated from field: string registration_token = 1;
     */
    registrationToken: string;
    /**
     * Certificate Signing Request (PEM)
     *
     * @generated from field: bytes csr = 2;
     */
    csr: Uint8Array<ArrayBuffer>;
    /**
     * @generated from field: string hostname = 3;
     */
    hostname: string;
    /**
     * @generated from field: string os_info = 4;
     */
    osInfo: string;
    constructor(data?: PartialMessage<RegisterRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RegisterRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RegisterRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RegisterRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RegisterRequest;
    static equals(a: RegisterRequest | PlainMessage<RegisterRequest> | undefined, b: RegisterRequest | PlainMessage<RegisterRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RegisterResponse
 */
export declare class RegisterResponse extends Message<RegisterResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    /**
     * @generated from field: optional string error_message = 2;
     */
    errorMessage?: string;
    /**
     * On success:
     *
     * Signed client certificate (PEM)
     *
     * @generated from field: bytes signed_certificate = 3;
     */
    signedCertificate: Uint8Array<ArrayBuffer>;
    /**
     * CA certificate for server verification (PEM)
     *
     * @generated from field: bytes ca_certificate = 4;
     */
    caCertificate: Uint8Array<ArrayBuffer>;
    /**
     * gRPC server address for future connections
     *
     * @generated from field: string server_address = 5;
     */
    serverAddress: string;
    /**
     * Assigned agent ID
     *
     * @generated from field: powermanage.v1.AgentId agent_id = 6;
     */
    agentId?: AgentId;
    constructor(data?: PartialMessage<RegisterResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RegisterResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RegisterResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RegisterResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RegisterResponse;
    static equals(a: RegisterResponse | PlainMessage<RegisterResponse> | undefined, b: RegisterResponse | PlainMessage<RegisterResponse> | undefined): boolean;
}
//# sourceMappingURL=agent_pb.d.ts.map