import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { Device } from "./devices_pb.js";
/**
 * How to match a condition
 *
 * @generated from enum powermanage.v1.MatchOperator
 */
export declare enum MatchOperator {
    /**
     * @generated from enum value: MATCH_OPERATOR_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Exact match
     *
     * @generated from enum value: MATCH_OPERATOR_EQUALS = 1;
     */
    EQUALS = 1,
    /**
     * Not equal
     *
     * @generated from enum value: MATCH_OPERATOR_NOT_EQUALS = 2;
     */
    NOT_EQUALS = 2,
    /**
     * String contains
     *
     * @generated from enum value: MATCH_OPERATOR_CONTAINS = 3;
     */
    CONTAINS = 3,
    /**
     * String starts with
     *
     * @generated from enum value: MATCH_OPERATOR_STARTS_WITH = 4;
     */
    STARTS_WITH = 4,
    /**
     * String ends with
     *
     * @generated from enum value: MATCH_OPERATOR_ENDS_WITH = 5;
     */
    ENDS_WITH = 5,
    /**
     * Regex match
     *
     * @generated from enum value: MATCH_OPERATOR_MATCHES = 6;
     */
    MATCHES = 6,
    /**
     * Label key exists (value ignored)
     *
     * @generated from enum value: MATCH_OPERATOR_EXISTS = 7;
     */
    EXISTS = 7,
    /**
     * Label key does not exist
     *
     * @generated from enum value: MATCH_OPERATOR_NOT_EXISTS = 8;
     */
    NOT_EXISTS = 8
}
/**
 * How to combine conditions
 *
 * @generated from enum powermanage.v1.QueryLogic
 */
export declare enum QueryLogic {
    /**
     * @generated from enum value: QUERY_LOGIC_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * All conditions must match
     *
     * @generated from enum value: QUERY_LOGIC_AND = 1;
     */
    AND = 1,
    /**
     * Any condition must match
     *
     * @generated from enum value: QUERY_LOGIC_OR = 2;
     */
    OR = 2
}
/**
 * Single condition in a query
 *
 * @generated from message powermanage.v1.DeviceQueryCondition
 */
export declare class DeviceQueryCondition extends Message<DeviceQueryCondition> {
    /**
     * Field to match against
     * Supported: "hostname", "os_info", "status", "labels.<key>"
     *
     * @generated from field: string field = 1;
     */
    field: string;
    /**
     * @generated from field: powermanage.v1.MatchOperator operator = 2;
     */
    operator: MatchOperator;
    /**
     * For EXISTS/NOT_EXISTS, this is ignored
     *
     * @generated from field: string value = 3;
     */
    value: string;
    constructor(data?: PartialMessage<DeviceQueryCondition>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeviceQueryCondition";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeviceQueryCondition;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeviceQueryCondition;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeviceQueryCondition;
    static equals(a: DeviceQueryCondition | PlainMessage<DeviceQueryCondition> | undefined, b: DeviceQueryCondition | PlainMessage<DeviceQueryCondition> | undefined): boolean;
}
/**
 * Query for dynamic device membership
 *
 * @generated from message powermanage.v1.DeviceQuery
 */
export declare class DeviceQuery extends Message<DeviceQuery> {
    /**
     * @generated from field: repeated powermanage.v1.DeviceQueryCondition conditions = 1;
     */
    conditions: DeviceQueryCondition[];
    /**
     * How to combine conditions (default AND)
     *
     * @generated from field: powermanage.v1.QueryLogic logic = 2;
     */
    logic: QueryLogic;
    constructor(data?: PartialMessage<DeviceQuery>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeviceQuery";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeviceQuery;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeviceQuery;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeviceQuery;
    static equals(a: DeviceQuery | PlainMessage<DeviceQuery> | undefined, b: DeviceQuery | PlainMessage<DeviceQuery> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeviceGroup
 */
export declare class DeviceGroup extends Message<DeviceGroup> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: string name = 2;
     */
    name: string;
    /**
     * @generated from field: string description = 3;
     */
    description: string;
    /**
     * @generated from field: powermanage.v1.DeviceQuery query = 4;
     */
    query?: DeviceQuery;
    /**
     * Cached member count (updated periodically)
     *
     * @generated from field: int32 member_count = 10;
     */
    memberCount: number;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp updated_at = 21;
     */
    updatedAt?: Timestamp;
    constructor(data?: PartialMessage<DeviceGroup>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeviceGroup";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeviceGroup;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeviceGroup;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeviceGroup;
    static equals(a: DeviceGroup | PlainMessage<DeviceGroup> | undefined, b: DeviceGroup | PlainMessage<DeviceGroup> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateDeviceGroupRequest
 */
export declare class CreateDeviceGroupRequest extends Message<CreateDeviceGroupRequest> {
    /**
     * @generated from field: string name = 1;
     */
    name: string;
    /**
     * @generated from field: string description = 2;
     */
    description: string;
    /**
     * @generated from field: powermanage.v1.DeviceQuery query = 3;
     */
    query?: DeviceQuery;
    constructor(data?: PartialMessage<CreateDeviceGroupRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateDeviceGroupRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateDeviceGroupRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateDeviceGroupRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateDeviceGroupRequest;
    static equals(a: CreateDeviceGroupRequest | PlainMessage<CreateDeviceGroupRequest> | undefined, b: CreateDeviceGroupRequest | PlainMessage<CreateDeviceGroupRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateDeviceGroupResponse
 */
export declare class CreateDeviceGroupResponse extends Message<CreateDeviceGroupResponse> {
    /**
     * @generated from field: powermanage.v1.DeviceGroup device_group = 1;
     */
    deviceGroup?: DeviceGroup;
    /**
     * Initial member count
     *
     * @generated from field: int32 member_count = 2;
     */
    memberCount: number;
    constructor(data?: PartialMessage<CreateDeviceGroupResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateDeviceGroupResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateDeviceGroupResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateDeviceGroupResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateDeviceGroupResponse;
    static equals(a: CreateDeviceGroupResponse | PlainMessage<CreateDeviceGroupResponse> | undefined, b: CreateDeviceGroupResponse | PlainMessage<CreateDeviceGroupResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceGroupRequest
 */
export declare class GetDeviceGroupRequest extends Message<GetDeviceGroupRequest> {
    /**
     * @generated from field: string group_id = 1;
     */
    groupId: string;
    constructor(data?: PartialMessage<GetDeviceGroupRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceGroupRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceGroupRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceGroupRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceGroupRequest;
    static equals(a: GetDeviceGroupRequest | PlainMessage<GetDeviceGroupRequest> | undefined, b: GetDeviceGroupRequest | PlainMessage<GetDeviceGroupRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceGroupResponse
 */
export declare class GetDeviceGroupResponse extends Message<GetDeviceGroupResponse> {
    /**
     * @generated from field: powermanage.v1.DeviceGroup device_group = 1;
     */
    deviceGroup?: DeviceGroup;
    constructor(data?: PartialMessage<GetDeviceGroupResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceGroupResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceGroupResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceGroupResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceGroupResponse;
    static equals(a: GetDeviceGroupResponse | PlainMessage<GetDeviceGroupResponse> | undefined, b: GetDeviceGroupResponse | PlainMessage<GetDeviceGroupResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDeviceGroupsRequest
 */
export declare class ListDeviceGroupsRequest extends Message<ListDeviceGroupsRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * Search by name
     *
     * @generated from field: optional string search = 3;
     */
    search?: string;
    constructor(data?: PartialMessage<ListDeviceGroupsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDeviceGroupsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDeviceGroupsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDeviceGroupsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDeviceGroupsRequest;
    static equals(a: ListDeviceGroupsRequest | PlainMessage<ListDeviceGroupsRequest> | undefined, b: ListDeviceGroupsRequest | PlainMessage<ListDeviceGroupsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDeviceGroupsResponse
 */
export declare class ListDeviceGroupsResponse extends Message<ListDeviceGroupsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.DeviceGroup device_groups = 1;
     */
    deviceGroups: DeviceGroup[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListDeviceGroupsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDeviceGroupsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDeviceGroupsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDeviceGroupsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDeviceGroupsResponse;
    static equals(a: ListDeviceGroupsResponse | PlainMessage<ListDeviceGroupsResponse> | undefined, b: ListDeviceGroupsResponse | PlainMessage<ListDeviceGroupsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDeviceGroupRequest
 */
export declare class UpdateDeviceGroupRequest extends Message<UpdateDeviceGroupRequest> {
    /**
     * @generated from field: string group_id = 1;
     */
    groupId: string;
    /**
     * @generated from field: optional string name = 2;
     */
    name?: string;
    /**
     * @generated from field: optional string description = 3;
     */
    description?: string;
    /**
     * @generated from field: optional powermanage.v1.DeviceQuery query = 4;
     */
    query?: DeviceQuery;
    constructor(data?: PartialMessage<UpdateDeviceGroupRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDeviceGroupRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDeviceGroupRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDeviceGroupRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDeviceGroupRequest;
    static equals(a: UpdateDeviceGroupRequest | PlainMessage<UpdateDeviceGroupRequest> | undefined, b: UpdateDeviceGroupRequest | PlainMessage<UpdateDeviceGroupRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDeviceGroupResponse
 */
export declare class UpdateDeviceGroupResponse extends Message<UpdateDeviceGroupResponse> {
    /**
     * @generated from field: powermanage.v1.DeviceGroup device_group = 1;
     */
    deviceGroup?: DeviceGroup;
    /**
     * Updated member count if query changed
     *
     * @generated from field: int32 member_count = 2;
     */
    memberCount: number;
    constructor(data?: PartialMessage<UpdateDeviceGroupResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDeviceGroupResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDeviceGroupResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDeviceGroupResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDeviceGroupResponse;
    static equals(a: UpdateDeviceGroupResponse | PlainMessage<UpdateDeviceGroupResponse> | undefined, b: UpdateDeviceGroupResponse | PlainMessage<UpdateDeviceGroupResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDeviceGroupRequest
 */
export declare class DeleteDeviceGroupRequest extends Message<DeleteDeviceGroupRequest> {
    /**
     * @generated from field: string group_id = 1;
     */
    groupId: string;
    constructor(data?: PartialMessage<DeleteDeviceGroupRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDeviceGroupRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDeviceGroupRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDeviceGroupRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDeviceGroupRequest;
    static equals(a: DeleteDeviceGroupRequest | PlainMessage<DeleteDeviceGroupRequest> | undefined, b: DeleteDeviceGroupRequest | PlainMessage<DeleteDeviceGroupRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDeviceGroupResponse
 */
export declare class DeleteDeviceGroupResponse extends Message<DeleteDeviceGroupResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteDeviceGroupResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDeviceGroupResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDeviceGroupResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDeviceGroupResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDeviceGroupResponse;
    static equals(a: DeleteDeviceGroupResponse | PlainMessage<DeleteDeviceGroupResponse> | undefined, b: DeleteDeviceGroupResponse | PlainMessage<DeleteDeviceGroupResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.PreviewDeviceGroupRequest
 */
export declare class PreviewDeviceGroupRequest extends Message<PreviewDeviceGroupRequest> {
    /**
     * @generated from field: powermanage.v1.DeviceQuery query = 1;
     */
    query?: DeviceQuery;
    /**
     * Max devices to return for preview
     *
     * @generated from field: int32 limit = 2;
     */
    limit: number;
    constructor(data?: PartialMessage<PreviewDeviceGroupRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PreviewDeviceGroupRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PreviewDeviceGroupRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PreviewDeviceGroupRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PreviewDeviceGroupRequest;
    static equals(a: PreviewDeviceGroupRequest | PlainMessage<PreviewDeviceGroupRequest> | undefined, b: PreviewDeviceGroupRequest | PlainMessage<PreviewDeviceGroupRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.PreviewDeviceGroupResponse
 */
export declare class PreviewDeviceGroupResponse extends Message<PreviewDeviceGroupResponse> {
    /**
     * @generated from field: repeated powermanage.v1.Device matching_devices = 1;
     */
    matchingDevices: Device[];
    /**
     * @generated from field: int32 total_matching = 2;
     */
    totalMatching: number;
    constructor(data?: PartialMessage<PreviewDeviceGroupResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.PreviewDeviceGroupResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PreviewDeviceGroupResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PreviewDeviceGroupResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PreviewDeviceGroupResponse;
    static equals(a: PreviewDeviceGroupResponse | PlainMessage<PreviewDeviceGroupResponse> | undefined, b: PreviewDeviceGroupResponse | PlainMessage<PreviewDeviceGroupResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceGroupMembersRequest
 */
export declare class GetDeviceGroupMembersRequest extends Message<GetDeviceGroupMembersRequest> {
    /**
     * @generated from field: string group_id = 1;
     */
    groupId: string;
    /**
     * @generated from field: int32 page_size = 2;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 3;
     */
    pageToken: string;
    constructor(data?: PartialMessage<GetDeviceGroupMembersRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceGroupMembersRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceGroupMembersRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceGroupMembersRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceGroupMembersRequest;
    static equals(a: GetDeviceGroupMembersRequest | PlainMessage<GetDeviceGroupMembersRequest> | undefined, b: GetDeviceGroupMembersRequest | PlainMessage<GetDeviceGroupMembersRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDeviceGroupMembersResponse
 */
export declare class GetDeviceGroupMembersResponse extends Message<GetDeviceGroupMembersResponse> {
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
    constructor(data?: PartialMessage<GetDeviceGroupMembersResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDeviceGroupMembersResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDeviceGroupMembersResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDeviceGroupMembersResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDeviceGroupMembersResponse;
    static equals(a: GetDeviceGroupMembersResponse | PlainMessage<GetDeviceGroupMembersResponse> | undefined, b: GetDeviceGroupMembersResponse | PlainMessage<GetDeviceGroupMembersResponse> | undefined): boolean;
}
//# sourceMappingURL=device_groups_pb.d.ts.map