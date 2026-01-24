import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { ActionId, ExecutionStatus } from "./common_pb.js";
/**
 * @generated from enum powermanage.v1.DeviceStatus
 */
export declare enum DeviceStatus {
    /**
     * @generated from enum value: DEVICE_STATUS_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Connected and responding
     *
     * @generated from enum value: DEVICE_STATUS_ONLINE = 1;
     */
    ONLINE = 1,
    /**
     * Not connected
     *
     * @generated from enum value: DEVICE_STATUS_OFFLINE = 2;
     */
    OFFLINE = 2,
    /**
     * Connected but in error state
     *
     * @generated from enum value: DEVICE_STATUS_ERROR = 3;
     */
    ERROR = 3,
    /**
     * Registered but never connected
     *
     * @generated from enum value: DEVICE_STATUS_PENDING = 4;
     */
    PENDING = 4
}
/**
 * @generated from message powermanage.v1.Device
 */
export declare class Device extends Message<Device> {
    /**
     * Same as AgentId
     *
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: string hostname = 2;
     */
    hostname: string;
    /**
     * @generated from field: string display_name = 3;
     */
    displayName: string;
    /**
     * @generated from field: string os_info = 4;
     */
    osInfo: string;
    /**
     * @generated from field: powermanage.v1.DeviceStatus status = 5;
     */
    status: DeviceStatus;
    /**
     * User-defined labels for grouping
     *
     * @generated from field: map<string, string> labels = 6;
     */
    labels: {
        [key: string]: string;
    };
    /**
     * Connection info
     *
     * @generated from field: optional google.protobuf.Timestamp last_seen_at = 10;
     */
    lastSeenAt?: Timestamp;
    /**
     * @generated from field: optional string agent_version = 11;
     */
    agentVersion?: string;
    /**
     * @generated from field: optional google.protobuf.Timestamp boot_time = 12;
     */
    bootTime?: Timestamp;
    /**
     * Certificate info
     *
     * @generated from field: google.protobuf.Timestamp cert_expires_at = 13;
     */
    certExpiresAt?: Timestamp;
    /**
     * Timestamps
     *
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp updated_at = 21;
     */
    updatedAt?: Timestamp;
    constructor(data?: PartialMessage<Device>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Device";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Device;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Device;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Device;
    static equals(a: Device | PlainMessage<Device> | undefined, b: Device | PlainMessage<Device> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDevicesRequest
 */
export declare class ListDevicesRequest extends Message<ListDevicesRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * Filter by status
     *
     * @generated from field: optional powermanage.v1.DeviceStatus status_filter = 3;
     */
    statusFilter?: DeviceStatus;
    /**
     * Filter by label (key=value)
     *
     * @generated from field: map<string, string> label_filter = 4;
     */
    labelFilter: {
        [key: string]: string;
    };
    /**
     * Search hostname/display_name
     *
     * @generated from field: optional string search = 5;
     */
    search?: string;
    constructor(data?: PartialMessage<ListDevicesRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDevicesRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDevicesRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDevicesRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDevicesRequest;
    static equals(a: ListDevicesRequest | PlainMessage<ListDevicesRequest> | undefined, b: ListDevicesRequest | PlainMessage<ListDevicesRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDevicesResponse
 */
export declare class ListDevicesResponse extends Message<ListDevicesResponse> {
    /**
     * @generated from field: repeated powermanage.v1.Device devices = 1;
     */
    devices: Device[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListDevicesResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDevicesResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDevicesResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDevicesResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDevicesResponse;
    static equals(a: ListDevicesResponse | PlainMessage<ListDevicesResponse> | undefined, b: ListDevicesResponse | PlainMessage<ListDevicesResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceRequest
 */
export declare class GetDeviceRequest extends Message<GetDeviceRequest> {
    /**
     * @generated from field: string device_id = 1;
     */
    deviceId: string;
    constructor(data?: PartialMessage<GetDeviceRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceRequest;
    static equals(a: GetDeviceRequest | PlainMessage<GetDeviceRequest> | undefined, b: GetDeviceRequest | PlainMessage<GetDeviceRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceResponse
 */
export declare class GetDeviceResponse extends Message<GetDeviceResponse> {
    /**
     * @generated from field: powermanage.v1.Device device = 1;
     */
    device?: Device;
    /**
     * Current action states for this device
     *
     * @generated from field: repeated powermanage.v1.ActionSummary action_summaries = 2;
     */
    actionSummaries: ActionSummary[];
    constructor(data?: PartialMessage<GetDeviceResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceResponse;
    static equals(a: GetDeviceResponse | PlainMessage<GetDeviceResponse> | undefined, b: GetDeviceResponse | PlainMessage<GetDeviceResponse> | undefined): boolean;
}
/**
 * Summary of an action assigned to a device
 *
 * @generated from message powermanage.v1.ActionSummary
 */
export declare class ActionSummary extends Message<ActionSummary> {
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 1;
     */
    actionId?: ActionId;
    /**
     * @generated from field: string action_name = 2;
     */
    actionName: string;
    /**
     * @generated from field: bool in_desired_state = 3;
     */
    inDesiredState: boolean;
    /**
     * @generated from field: optional google.protobuf.Timestamp last_executed = 4;
     */
    lastExecuted?: Timestamp;
    /**
     * @generated from field: optional powermanage.v1.ExecutionStatus last_status = 5;
     */
    lastStatus?: ExecutionStatus;
    constructor(data?: PartialMessage<ActionSummary>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionSummary";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionSummary;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionSummary;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionSummary;
    static equals(a: ActionSummary | PlainMessage<ActionSummary> | undefined, b: ActionSummary | PlainMessage<ActionSummary> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDeviceRequest
 */
export declare class UpdateDeviceRequest extends Message<UpdateDeviceRequest> {
    /**
     * @generated from field: string device_id = 1;
     */
    deviceId: string;
    /**
     * @generated from field: optional string display_name = 2;
     */
    displayName?: string;
    /**
     * Labels to set (replaces all labels)
     *
     * @generated from field: map<string, string> labels = 3;
     */
    labels: {
        [key: string]: string;
    };
    /**
     * If true, only update provided labels without removing existing ones
     *
     * @generated from field: bool merge_labels = 4;
     */
    mergeLabels: boolean;
    constructor(data?: PartialMessage<UpdateDeviceRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDeviceRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDeviceRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDeviceRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDeviceRequest;
    static equals(a: UpdateDeviceRequest | PlainMessage<UpdateDeviceRequest> | undefined, b: UpdateDeviceRequest | PlainMessage<UpdateDeviceRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDeviceResponse
 */
export declare class UpdateDeviceResponse extends Message<UpdateDeviceResponse> {
    /**
     * @generated from field: powermanage.v1.Device device = 1;
     */
    device?: Device;
    constructor(data?: PartialMessage<UpdateDeviceResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDeviceResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDeviceResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDeviceResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDeviceResponse;
    static equals(a: UpdateDeviceResponse | PlainMessage<UpdateDeviceResponse> | undefined, b: UpdateDeviceResponse | PlainMessage<UpdateDeviceResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDeviceRequest
 */
export declare class DeleteDeviceRequest extends Message<DeleteDeviceRequest> {
    /**
     * @generated from field: string device_id = 1;
     */
    deviceId: string;
    constructor(data?: PartialMessage<DeleteDeviceRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDeviceRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDeviceRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDeviceRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDeviceRequest;
    static equals(a: DeleteDeviceRequest | PlainMessage<DeleteDeviceRequest> | undefined, b: DeleteDeviceRequest | PlainMessage<DeleteDeviceRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDeviceResponse
 */
export declare class DeleteDeviceResponse extends Message<DeleteDeviceResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteDeviceResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDeviceResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDeviceResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDeviceResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDeviceResponse;
    static equals(a: DeleteDeviceResponse | PlainMessage<DeleteDeviceResponse> | undefined, b: DeleteDeviceResponse | PlainMessage<DeleteDeviceResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RegistrationToken
 */
export declare class RegistrationToken extends Message<RegistrationToken> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * The actual token for agent registration
     *
     * @generated from field: string token = 2;
     */
    token: string;
    /**
     * Admin note about what this is for
     *
     * @generated from field: string description = 3;
     */
    description: string;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 4;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp expires_at = 5;
     */
    expiresAt?: Timestamp;
    /**
     * @generated from field: bool used = 6;
     */
    used: boolean;
    /**
     * @generated from field: optional google.protobuf.Timestamp used_at = 7;
     */
    usedAt?: Timestamp;
    /**
     * Device that used this token
     *
     * @generated from field: optional string device_id = 8;
     */
    deviceId?: string;
    constructor(data?: PartialMessage<RegistrationToken>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RegistrationToken";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RegistrationToken;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RegistrationToken;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RegistrationToken;
    static equals(a: RegistrationToken | PlainMessage<RegistrationToken> | undefined, b: RegistrationToken | PlainMessage<RegistrationToken> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateRegistrationTokenRequest
 */
export declare class CreateRegistrationTokenRequest extends Message<CreateRegistrationTokenRequest> {
    /**
     * @generated from field: string description = 1;
     */
    description: string;
    /**
     * Duration in seconds (default 24h)
     *
     * @generated from field: optional int64 expires_in_seconds = 2;
     */
    expiresInSeconds?: bigint;
    constructor(data?: PartialMessage<CreateRegistrationTokenRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateRegistrationTokenRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateRegistrationTokenRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateRegistrationTokenRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateRegistrationTokenRequest;
    static equals(a: CreateRegistrationTokenRequest | PlainMessage<CreateRegistrationTokenRequest> | undefined, b: CreateRegistrationTokenRequest | PlainMessage<CreateRegistrationTokenRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateRegistrationTokenResponse
 */
export declare class CreateRegistrationTokenResponse extends Message<CreateRegistrationTokenResponse> {
    /**
     * @generated from field: powermanage.v1.RegistrationToken registration_token = 1;
     */
    registrationToken?: RegistrationToken;
    constructor(data?: PartialMessage<CreateRegistrationTokenResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateRegistrationTokenResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateRegistrationTokenResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateRegistrationTokenResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateRegistrationTokenResponse;
    static equals(a: CreateRegistrationTokenResponse | PlainMessage<CreateRegistrationTokenResponse> | undefined, b: CreateRegistrationTokenResponse | PlainMessage<CreateRegistrationTokenResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListRegistrationTokensRequest
 */
export declare class ListRegistrationTokensRequest extends Message<ListRegistrationTokensRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * @generated from field: optional bool include_used = 3;
     */
    includeUsed?: boolean;
    /**
     * @generated from field: optional bool include_expired = 4;
     */
    includeExpired?: boolean;
    constructor(data?: PartialMessage<ListRegistrationTokensRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListRegistrationTokensRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListRegistrationTokensRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListRegistrationTokensRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListRegistrationTokensRequest;
    static equals(a: ListRegistrationTokensRequest | PlainMessage<ListRegistrationTokensRequest> | undefined, b: ListRegistrationTokensRequest | PlainMessage<ListRegistrationTokensRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListRegistrationTokensResponse
 */
export declare class ListRegistrationTokensResponse extends Message<ListRegistrationTokensResponse> {
    /**
     * @generated from field: repeated powermanage.v1.RegistrationToken registration_tokens = 1;
     */
    registrationTokens: RegistrationToken[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    constructor(data?: PartialMessage<ListRegistrationTokensResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListRegistrationTokensResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListRegistrationTokensResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListRegistrationTokensResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListRegistrationTokensResponse;
    static equals(a: ListRegistrationTokensResponse | PlainMessage<ListRegistrationTokensResponse> | undefined, b: ListRegistrationTokensResponse | PlainMessage<ListRegistrationTokensResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeRegistrationTokenRequest
 */
export declare class RevokeRegistrationTokenRequest extends Message<RevokeRegistrationTokenRequest> {
    /**
     * @generated from field: string token_id = 1;
     */
    tokenId: string;
    constructor(data?: PartialMessage<RevokeRegistrationTokenRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeRegistrationTokenRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeRegistrationTokenRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeRegistrationTokenRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeRegistrationTokenRequest;
    static equals(a: RevokeRegistrationTokenRequest | PlainMessage<RevokeRegistrationTokenRequest> | undefined, b: RevokeRegistrationTokenRequest | PlainMessage<RevokeRegistrationTokenRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeRegistrationTokenResponse
 */
export declare class RevokeRegistrationTokenResponse extends Message<RevokeRegistrationTokenResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<RevokeRegistrationTokenResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeRegistrationTokenResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeRegistrationTokenResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeRegistrationTokenResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeRegistrationTokenResponse;
    static equals(a: RevokeRegistrationTokenResponse | PlainMessage<RevokeRegistrationTokenResponse> | undefined, b: RevokeRegistrationTokenResponse | PlainMessage<RevokeRegistrationTokenResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceHistoryRequest
 */
export declare class GetDeviceHistoryRequest extends Message<GetDeviceHistoryRequest> {
    /**
     * @generated from field: string device_id = 1;
     */
    deviceId: string;
    /**
     * @generated from field: int32 page_size = 2;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 3;
     */
    pageToken: string;
    /**
     * Filter by action
     *
     * @generated from field: optional string action_id = 4;
     */
    actionId?: string;
    /**
     * Filter by time range
     *
     * @generated from field: optional google.protobuf.Timestamp from = 5;
     */
    from?: Timestamp;
    /**
     * @generated from field: optional google.protobuf.Timestamp to = 6;
     */
    to?: Timestamp;
    constructor(data?: PartialMessage<GetDeviceHistoryRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceHistoryRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceHistoryRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceHistoryRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceHistoryRequest;
    static equals(a: GetDeviceHistoryRequest | PlainMessage<GetDeviceHistoryRequest> | undefined, b: GetDeviceHistoryRequest | PlainMessage<GetDeviceHistoryRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceHistoryResponse
 */
export declare class GetDeviceHistoryResponse extends Message<GetDeviceHistoryResponse> {
    /**
     * @generated from field: repeated powermanage.v1.DeviceHistoryEntry entries = 1;
     */
    entries: DeviceHistoryEntry[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    constructor(data?: PartialMessage<GetDeviceHistoryResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceHistoryResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceHistoryResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceHistoryResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceHistoryResponse;
    static equals(a: GetDeviceHistoryResponse | PlainMessage<GetDeviceHistoryResponse> | undefined, b: GetDeviceHistoryResponse | PlainMessage<GetDeviceHistoryResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeviceHistoryEntry
 */
export declare class DeviceHistoryEntry extends Message<DeviceHistoryEntry> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: powermanage.v1.ActionId action_id = 2;
     */
    actionId?: ActionId;
    /**
     * @generated from field: powermanage.v1.ExecutionStatus status = 3;
     */
    status: ExecutionStatus;
    /**
     * @generated from field: optional string error_message = 4;
     */
    errorMessage?: string;
    /**
     * @generated from field: int64 duration_ms = 5;
     */
    durationMs: bigint;
    /**
     * @generated from field: google.protobuf.Timestamp executed_at = 6;
     */
    executedAt?: Timestamp;
    /**
     * @generated from field: bool is_reconciliation_run = 7;
     */
    isReconciliationRun: boolean;
    constructor(data?: PartialMessage<DeviceHistoryEntry>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeviceHistoryEntry";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeviceHistoryEntry;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeviceHistoryEntry;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeviceHistoryEntry;
    static equals(a: DeviceHistoryEntry | PlainMessage<DeviceHistoryEntry> | undefined, b: DeviceHistoryEntry | PlainMessage<DeviceHistoryEntry> | undefined): boolean;
}
//# sourceMappingURL=devices_pb.d.ts.map