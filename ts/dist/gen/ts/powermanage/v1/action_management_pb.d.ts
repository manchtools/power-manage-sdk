import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { Action, ActionType, PackageActionParams } from "./actions_pb.js";
/**
 * What is being assigned
 *
 * @generated from enum powermanage.v1.AssignmentSourceType
 */
export declare enum AssignmentSourceType {
    /**
     * @generated from enum value: ASSIGNMENT_SOURCE_TYPE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: ASSIGNMENT_SOURCE_TYPE_ACTION = 1;
     */
    ACTION = 1,
    /**
     * @generated from enum value: ASSIGNMENT_SOURCE_TYPE_ACTION_SET = 2;
     */
    ACTION_SET = 2,
    /**
     * @generated from enum value: ASSIGNMENT_SOURCE_TYPE_DEFINITION = 3;
     */
    DEFINITION = 3
}
/**
 * What it's being assigned to
 *
 * @generated from enum powermanage.v1.AssignmentTargetType
 */
export declare enum AssignmentTargetType {
    /**
     * @generated from enum value: ASSIGNMENT_TARGET_TYPE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * @generated from enum value: ASSIGNMENT_TARGET_TYPE_DEVICE = 1;
     */
    DEVICE = 1,
    /**
     * @generated from enum value: ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP = 2;
     */
    DEVICE_GROUP = 2
}
/**
 * Assignment state determines how actions are presented/enforced
 *
 * @generated from enum powermanage.v1.AssignmentState
 */
export declare enum AssignmentState {
    /**
     * @generated from enum value: ASSIGNMENT_STATE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Must be applied, auto-enforced by agent
     *
     * @generated from enum value: ASSIGNMENT_STATE_REQUIRED = 1;
     */
    REQUIRED = 1,
    /**
     * User can trigger manually from web app
     *
     * @generated from enum value: ASSIGNMENT_STATE_AVAILABLE = 2;
     */
    AVAILABLE = 2,
    /**
     * Must NOT be present, agent will remove
     *
     * @generated from enum value: ASSIGNMENT_STATE_ABSENT = 3;
     */
    ABSENT = 3
}
/**
 * @generated from message powermanage.v1.ManagedAction
 */
export declare class ManagedAction extends Message<ManagedAction> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * Human-readable name
     *
     * @generated from field: string name = 2;
     */
    name: string;
    /**
     * @generated from field: string description = 3;
     */
    description: string;
    /**
     * @generated from field: powermanage.v1.ActionType type = 4;
     */
    type: ActionType;
    /**
     * Action parameters
     *
     * @generated from oneof powermanage.v1.ManagedAction.params
     */
    params: {
        /**
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
    constructor(data?: PartialMessage<ManagedAction>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ManagedAction";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ManagedAction;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ManagedAction;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ManagedAction;
    static equals(a: ManagedAction | PlainMessage<ManagedAction> | undefined, b: ManagedAction | PlainMessage<ManagedAction> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateManagedActionRequest
 */
export declare class CreateManagedActionRequest extends Message<CreateManagedActionRequest> {
    /**
     * @generated from field: string name = 1;
     */
    name: string;
    /**
     * @generated from field: string description = 2;
     */
    description: string;
    /**
     * @generated from field: powermanage.v1.ActionType type = 3;
     */
    type: ActionType;
    /**
     * @generated from oneof powermanage.v1.CreateManagedActionRequest.params
     */
    params: {
        /**
         * @generated from field: powermanage.v1.PackageActionParams package_params = 10;
         */
        value: PackageActionParams;
        case: "packageParams";
    } | {
        case: undefined;
        value?: undefined;
    };
    constructor(data?: PartialMessage<CreateManagedActionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateManagedActionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateManagedActionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateManagedActionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateManagedActionRequest;
    static equals(a: CreateManagedActionRequest | PlainMessage<CreateManagedActionRequest> | undefined, b: CreateManagedActionRequest | PlainMessage<CreateManagedActionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateManagedActionResponse
 */
export declare class CreateManagedActionResponse extends Message<CreateManagedActionResponse> {
    /**
     * @generated from field: powermanage.v1.ManagedAction managed_action = 1;
     */
    managedAction?: ManagedAction;
    constructor(data?: PartialMessage<CreateManagedActionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateManagedActionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateManagedActionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateManagedActionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateManagedActionResponse;
    static equals(a: CreateManagedActionResponse | PlainMessage<CreateManagedActionResponse> | undefined, b: CreateManagedActionResponse | PlainMessage<CreateManagedActionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetManagedActionRequest
 */
export declare class GetManagedActionRequest extends Message<GetManagedActionRequest> {
    /**
     * @generated from field: string action_id = 1;
     */
    actionId: string;
    constructor(data?: PartialMessage<GetManagedActionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetManagedActionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetManagedActionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetManagedActionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetManagedActionRequest;
    static equals(a: GetManagedActionRequest | PlainMessage<GetManagedActionRequest> | undefined, b: GetManagedActionRequest | PlainMessage<GetManagedActionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetManagedActionResponse
 */
export declare class GetManagedActionResponse extends Message<GetManagedActionResponse> {
    /**
     * @generated from field: powermanage.v1.ManagedAction managed_action = 1;
     */
    managedAction?: ManagedAction;
    constructor(data?: PartialMessage<GetManagedActionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetManagedActionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetManagedActionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetManagedActionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetManagedActionResponse;
    static equals(a: GetManagedActionResponse | PlainMessage<GetManagedActionResponse> | undefined, b: GetManagedActionResponse | PlainMessage<GetManagedActionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListManagedActionsRequest
 */
export declare class ListManagedActionsRequest extends Message<ListManagedActionsRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * @generated from field: optional powermanage.v1.ActionType type_filter = 3;
     */
    typeFilter?: ActionType;
    /**
     * @generated from field: optional string search = 4;
     */
    search?: string;
    constructor(data?: PartialMessage<ListManagedActionsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListManagedActionsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListManagedActionsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListManagedActionsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListManagedActionsRequest;
    static equals(a: ListManagedActionsRequest | PlainMessage<ListManagedActionsRequest> | undefined, b: ListManagedActionsRequest | PlainMessage<ListManagedActionsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListManagedActionsResponse
 */
export declare class ListManagedActionsResponse extends Message<ListManagedActionsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.ManagedAction managed_actions = 1;
     */
    managedActions: ManagedAction[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListManagedActionsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListManagedActionsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListManagedActionsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListManagedActionsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListManagedActionsResponse;
    static equals(a: ListManagedActionsResponse | PlainMessage<ListManagedActionsResponse> | undefined, b: ListManagedActionsResponse | PlainMessage<ListManagedActionsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateManagedActionRequest
 */
export declare class UpdateManagedActionRequest extends Message<UpdateManagedActionRequest> {
    /**
     * @generated from field: string action_id = 1;
     */
    actionId: string;
    /**
     * @generated from field: optional string name = 2;
     */
    name?: string;
    /**
     * @generated from field: optional string description = 3;
     */
    description?: string;
    /**
     * @generated from oneof powermanage.v1.UpdateManagedActionRequest.params
     */
    params: {
        /**
         * @generated from field: powermanage.v1.PackageActionParams package_params = 10;
         */
        value: PackageActionParams;
        case: "packageParams";
    } | {
        case: undefined;
        value?: undefined;
    };
    constructor(data?: PartialMessage<UpdateManagedActionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateManagedActionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateManagedActionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateManagedActionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateManagedActionRequest;
    static equals(a: UpdateManagedActionRequest | PlainMessage<UpdateManagedActionRequest> | undefined, b: UpdateManagedActionRequest | PlainMessage<UpdateManagedActionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateManagedActionResponse
 */
export declare class UpdateManagedActionResponse extends Message<UpdateManagedActionResponse> {
    /**
     * @generated from field: powermanage.v1.ManagedAction managed_action = 1;
     */
    managedAction?: ManagedAction;
    constructor(data?: PartialMessage<UpdateManagedActionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateManagedActionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateManagedActionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateManagedActionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateManagedActionResponse;
    static equals(a: UpdateManagedActionResponse | PlainMessage<UpdateManagedActionResponse> | undefined, b: UpdateManagedActionResponse | PlainMessage<UpdateManagedActionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteManagedActionRequest
 */
export declare class DeleteManagedActionRequest extends Message<DeleteManagedActionRequest> {
    /**
     * @generated from field: string action_id = 1;
     */
    actionId: string;
    constructor(data?: PartialMessage<DeleteManagedActionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteManagedActionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteManagedActionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteManagedActionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteManagedActionRequest;
    static equals(a: DeleteManagedActionRequest | PlainMessage<DeleteManagedActionRequest> | undefined, b: DeleteManagedActionRequest | PlainMessage<DeleteManagedActionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteManagedActionResponse
 */
export declare class DeleteManagedActionResponse extends Message<DeleteManagedActionResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteManagedActionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteManagedActionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteManagedActionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteManagedActionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteManagedActionResponse;
    static equals(a: DeleteManagedActionResponse | PlainMessage<DeleteManagedActionResponse> | undefined, b: DeleteManagedActionResponse | PlainMessage<DeleteManagedActionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ActionSet
 */
export declare class ActionSet extends Message<ActionSet> {
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
     * Actions in this set
     *
     * @generated from field: repeated powermanage.v1.ManagedAction actions = 10;
     */
    actions: ManagedAction[];
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp updated_at = 21;
     */
    updatedAt?: Timestamp;
    constructor(data?: PartialMessage<ActionSet>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ActionSet";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ActionSet;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ActionSet;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ActionSet;
    static equals(a: ActionSet | PlainMessage<ActionSet> | undefined, b: ActionSet | PlainMessage<ActionSet> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateActionSetRequest
 */
export declare class CreateActionSetRequest extends Message<CreateActionSetRequest> {
    /**
     * @generated from field: string name = 1;
     */
    name: string;
    /**
     * @generated from field: string description = 2;
     */
    description: string;
    /**
     * Initial action IDs to include
     *
     * @generated from field: repeated string action_ids = 3;
     */
    actionIds: string[];
    constructor(data?: PartialMessage<CreateActionSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateActionSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateActionSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateActionSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateActionSetRequest;
    static equals(a: CreateActionSetRequest | PlainMessage<CreateActionSetRequest> | undefined, b: CreateActionSetRequest | PlainMessage<CreateActionSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateActionSetResponse
 */
export declare class CreateActionSetResponse extends Message<CreateActionSetResponse> {
    /**
     * @generated from field: powermanage.v1.ActionSet action_set = 1;
     */
    actionSet?: ActionSet;
    constructor(data?: PartialMessage<CreateActionSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateActionSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateActionSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateActionSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateActionSetResponse;
    static equals(a: CreateActionSetResponse | PlainMessage<CreateActionSetResponse> | undefined, b: CreateActionSetResponse | PlainMessage<CreateActionSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetActionSetRequest
 */
export declare class GetActionSetRequest extends Message<GetActionSetRequest> {
    /**
     * @generated from field: string action_set_id = 1;
     */
    actionSetId: string;
    constructor(data?: PartialMessage<GetActionSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetActionSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetActionSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetActionSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetActionSetRequest;
    static equals(a: GetActionSetRequest | PlainMessage<GetActionSetRequest> | undefined, b: GetActionSetRequest | PlainMessage<GetActionSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetActionSetResponse
 */
export declare class GetActionSetResponse extends Message<GetActionSetResponse> {
    /**
     * @generated from field: powermanage.v1.ActionSet action_set = 1;
     */
    actionSet?: ActionSet;
    constructor(data?: PartialMessage<GetActionSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetActionSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetActionSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetActionSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetActionSetResponse;
    static equals(a: GetActionSetResponse | PlainMessage<GetActionSetResponse> | undefined, b: GetActionSetResponse | PlainMessage<GetActionSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListActionSetsRequest
 */
export declare class ListActionSetsRequest extends Message<ListActionSetsRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * @generated from field: optional string search = 3;
     */
    search?: string;
    constructor(data?: PartialMessage<ListActionSetsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListActionSetsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListActionSetsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListActionSetsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListActionSetsRequest;
    static equals(a: ListActionSetsRequest | PlainMessage<ListActionSetsRequest> | undefined, b: ListActionSetsRequest | PlainMessage<ListActionSetsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListActionSetsResponse
 */
export declare class ListActionSetsResponse extends Message<ListActionSetsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.ActionSet action_sets = 1;
     */
    actionSets: ActionSet[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListActionSetsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListActionSetsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListActionSetsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListActionSetsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListActionSetsResponse;
    static equals(a: ListActionSetsResponse | PlainMessage<ListActionSetsResponse> | undefined, b: ListActionSetsResponse | PlainMessage<ListActionSetsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateActionSetRequest
 */
export declare class UpdateActionSetRequest extends Message<UpdateActionSetRequest> {
    /**
     * @generated from field: string action_set_id = 1;
     */
    actionSetId: string;
    /**
     * @generated from field: optional string name = 2;
     */
    name?: string;
    /**
     * @generated from field: optional string description = 3;
     */
    description?: string;
    constructor(data?: PartialMessage<UpdateActionSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateActionSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateActionSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateActionSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateActionSetRequest;
    static equals(a: UpdateActionSetRequest | PlainMessage<UpdateActionSetRequest> | undefined, b: UpdateActionSetRequest | PlainMessage<UpdateActionSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateActionSetResponse
 */
export declare class UpdateActionSetResponse extends Message<UpdateActionSetResponse> {
    /**
     * @generated from field: powermanage.v1.ActionSet action_set = 1;
     */
    actionSet?: ActionSet;
    constructor(data?: PartialMessage<UpdateActionSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateActionSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateActionSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateActionSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateActionSetResponse;
    static equals(a: UpdateActionSetResponse | PlainMessage<UpdateActionSetResponse> | undefined, b: UpdateActionSetResponse | PlainMessage<UpdateActionSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteActionSetRequest
 */
export declare class DeleteActionSetRequest extends Message<DeleteActionSetRequest> {
    /**
     * @generated from field: string action_set_id = 1;
     */
    actionSetId: string;
    constructor(data?: PartialMessage<DeleteActionSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteActionSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteActionSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteActionSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteActionSetRequest;
    static equals(a: DeleteActionSetRequest | PlainMessage<DeleteActionSetRequest> | undefined, b: DeleteActionSetRequest | PlainMessage<DeleteActionSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteActionSetResponse
 */
export declare class DeleteActionSetResponse extends Message<DeleteActionSetResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteActionSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteActionSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteActionSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteActionSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteActionSetResponse;
    static equals(a: DeleteActionSetResponse | PlainMessage<DeleteActionSetResponse> | undefined, b: DeleteActionSetResponse | PlainMessage<DeleteActionSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AddActionsToSetRequest
 */
export declare class AddActionsToSetRequest extends Message<AddActionsToSetRequest> {
    /**
     * @generated from field: string action_set_id = 1;
     */
    actionSetId: string;
    /**
     * @generated from field: repeated string action_ids = 2;
     */
    actionIds: string[];
    constructor(data?: PartialMessage<AddActionsToSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AddActionsToSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AddActionsToSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AddActionsToSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AddActionsToSetRequest;
    static equals(a: AddActionsToSetRequest | PlainMessage<AddActionsToSetRequest> | undefined, b: AddActionsToSetRequest | PlainMessage<AddActionsToSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AddActionsToSetResponse
 */
export declare class AddActionsToSetResponse extends Message<AddActionsToSetResponse> {
    /**
     * @generated from field: powermanage.v1.ActionSet action_set = 1;
     */
    actionSet?: ActionSet;
    constructor(data?: PartialMessage<AddActionsToSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AddActionsToSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AddActionsToSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AddActionsToSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AddActionsToSetResponse;
    static equals(a: AddActionsToSetResponse | PlainMessage<AddActionsToSetResponse> | undefined, b: AddActionsToSetResponse | PlainMessage<AddActionsToSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RemoveActionsFromSetRequest
 */
export declare class RemoveActionsFromSetRequest extends Message<RemoveActionsFromSetRequest> {
    /**
     * @generated from field: string action_set_id = 1;
     */
    actionSetId: string;
    /**
     * @generated from field: repeated string action_ids = 2;
     */
    actionIds: string[];
    constructor(data?: PartialMessage<RemoveActionsFromSetRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RemoveActionsFromSetRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RemoveActionsFromSetRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RemoveActionsFromSetRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RemoveActionsFromSetRequest;
    static equals(a: RemoveActionsFromSetRequest | PlainMessage<RemoveActionsFromSetRequest> | undefined, b: RemoveActionsFromSetRequest | PlainMessage<RemoveActionsFromSetRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RemoveActionsFromSetResponse
 */
export declare class RemoveActionsFromSetResponse extends Message<RemoveActionsFromSetResponse> {
    /**
     * @generated from field: powermanage.v1.ActionSet action_set = 1;
     */
    actionSet?: ActionSet;
    constructor(data?: PartialMessage<RemoveActionsFromSetResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RemoveActionsFromSetResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RemoveActionsFromSetResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RemoveActionsFromSetResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RemoveActionsFromSetResponse;
    static equals(a: RemoveActionsFromSetResponse | PlainMessage<RemoveActionsFromSetResponse> | undefined, b: RemoveActionsFromSetResponse | PlainMessage<RemoveActionsFromSetResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.Definition
 */
export declare class Definition extends Message<Definition> {
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
     * Action sets in this definition
     *
     * @generated from field: repeated powermanage.v1.ActionSet action_sets = 10;
     */
    actionSets: ActionSet[];
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp updated_at = 21;
     */
    updatedAt?: Timestamp;
    constructor(data?: PartialMessage<Definition>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Definition";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Definition;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Definition;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Definition;
    static equals(a: Definition | PlainMessage<Definition> | undefined, b: Definition | PlainMessage<Definition> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateDefinitionRequest
 */
export declare class CreateDefinitionRequest extends Message<CreateDefinitionRequest> {
    /**
     * @generated from field: string name = 1;
     */
    name: string;
    /**
     * @generated from field: string description = 2;
     */
    description: string;
    /**
     * Initial action set IDs to include
     *
     * @generated from field: repeated string action_set_ids = 3;
     */
    actionSetIds: string[];
    constructor(data?: PartialMessage<CreateDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateDefinitionRequest;
    static equals(a: CreateDefinitionRequest | PlainMessage<CreateDefinitionRequest> | undefined, b: CreateDefinitionRequest | PlainMessage<CreateDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateDefinitionResponse
 */
export declare class CreateDefinitionResponse extends Message<CreateDefinitionResponse> {
    /**
     * @generated from field: powermanage.v1.Definition definition = 1;
     */
    definition?: Definition;
    constructor(data?: PartialMessage<CreateDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateDefinitionResponse;
    static equals(a: CreateDefinitionResponse | PlainMessage<CreateDefinitionResponse> | undefined, b: CreateDefinitionResponse | PlainMessage<CreateDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDefinitionRequest
 */
export declare class GetDefinitionRequest extends Message<GetDefinitionRequest> {
    /**
     * @generated from field: string definition_id = 1;
     */
    definitionId: string;
    constructor(data?: PartialMessage<GetDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDefinitionRequest;
    static equals(a: GetDefinitionRequest | PlainMessage<GetDefinitionRequest> | undefined, b: GetDefinitionRequest | PlainMessage<GetDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetDefinitionResponse
 */
export declare class GetDefinitionResponse extends Message<GetDefinitionResponse> {
    /**
     * @generated from field: powermanage.v1.Definition definition = 1;
     */
    definition?: Definition;
    constructor(data?: PartialMessage<GetDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetDefinitionResponse;
    static equals(a: GetDefinitionResponse | PlainMessage<GetDefinitionResponse> | undefined, b: GetDefinitionResponse | PlainMessage<GetDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDefinitionsRequest
 */
export declare class ListDefinitionsRequest extends Message<ListDefinitionsRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * @generated from field: optional string search = 3;
     */
    search?: string;
    constructor(data?: PartialMessage<ListDefinitionsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDefinitionsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDefinitionsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDefinitionsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDefinitionsRequest;
    static equals(a: ListDefinitionsRequest | PlainMessage<ListDefinitionsRequest> | undefined, b: ListDefinitionsRequest | PlainMessage<ListDefinitionsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListDefinitionsResponse
 */
export declare class ListDefinitionsResponse extends Message<ListDefinitionsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.Definition definitions = 1;
     */
    definitions: Definition[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListDefinitionsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListDefinitionsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListDefinitionsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListDefinitionsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListDefinitionsResponse;
    static equals(a: ListDefinitionsResponse | PlainMessage<ListDefinitionsResponse> | undefined, b: ListDefinitionsResponse | PlainMessage<ListDefinitionsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDefinitionRequest
 */
export declare class UpdateDefinitionRequest extends Message<UpdateDefinitionRequest> {
    /**
     * @generated from field: string definition_id = 1;
     */
    definitionId: string;
    /**
     * @generated from field: optional string name = 2;
     */
    name?: string;
    /**
     * @generated from field: optional string description = 3;
     */
    description?: string;
    constructor(data?: PartialMessage<UpdateDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDefinitionRequest;
    static equals(a: UpdateDefinitionRequest | PlainMessage<UpdateDefinitionRequest> | undefined, b: UpdateDefinitionRequest | PlainMessage<UpdateDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateDefinitionResponse
 */
export declare class UpdateDefinitionResponse extends Message<UpdateDefinitionResponse> {
    /**
     * @generated from field: powermanage.v1.Definition definition = 1;
     */
    definition?: Definition;
    constructor(data?: PartialMessage<UpdateDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateDefinitionResponse;
    static equals(a: UpdateDefinitionResponse | PlainMessage<UpdateDefinitionResponse> | undefined, b: UpdateDefinitionResponse | PlainMessage<UpdateDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDefinitionRequest
 */
export declare class DeleteDefinitionRequest extends Message<DeleteDefinitionRequest> {
    /**
     * @generated from field: string definition_id = 1;
     */
    definitionId: string;
    constructor(data?: PartialMessage<DeleteDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDefinitionRequest;
    static equals(a: DeleteDefinitionRequest | PlainMessage<DeleteDefinitionRequest> | undefined, b: DeleteDefinitionRequest | PlainMessage<DeleteDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteDefinitionResponse
 */
export declare class DeleteDefinitionResponse extends Message<DeleteDefinitionResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteDefinitionResponse;
    static equals(a: DeleteDefinitionResponse | PlainMessage<DeleteDefinitionResponse> | undefined, b: DeleteDefinitionResponse | PlainMessage<DeleteDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AddActionSetsToDefinitionRequest
 */
export declare class AddActionSetsToDefinitionRequest extends Message<AddActionSetsToDefinitionRequest> {
    /**
     * @generated from field: string definition_id = 1;
     */
    definitionId: string;
    /**
     * @generated from field: repeated string action_set_ids = 2;
     */
    actionSetIds: string[];
    constructor(data?: PartialMessage<AddActionSetsToDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AddActionSetsToDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AddActionSetsToDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AddActionSetsToDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AddActionSetsToDefinitionRequest;
    static equals(a: AddActionSetsToDefinitionRequest | PlainMessage<AddActionSetsToDefinitionRequest> | undefined, b: AddActionSetsToDefinitionRequest | PlainMessage<AddActionSetsToDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.AddActionSetsToDefinitionResponse
 */
export declare class AddActionSetsToDefinitionResponse extends Message<AddActionSetsToDefinitionResponse> {
    /**
     * @generated from field: powermanage.v1.Definition definition = 1;
     */
    definition?: Definition;
    constructor(data?: PartialMessage<AddActionSetsToDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AddActionSetsToDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AddActionSetsToDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AddActionSetsToDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AddActionSetsToDefinitionResponse;
    static equals(a: AddActionSetsToDefinitionResponse | PlainMessage<AddActionSetsToDefinitionResponse> | undefined, b: AddActionSetsToDefinitionResponse | PlainMessage<AddActionSetsToDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RemoveActionSetsFromDefinitionRequest
 */
export declare class RemoveActionSetsFromDefinitionRequest extends Message<RemoveActionSetsFromDefinitionRequest> {
    /**
     * @generated from field: string definition_id = 1;
     */
    definitionId: string;
    /**
     * @generated from field: repeated string action_set_ids = 2;
     */
    actionSetIds: string[];
    constructor(data?: PartialMessage<RemoveActionSetsFromDefinitionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RemoveActionSetsFromDefinitionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RemoveActionSetsFromDefinitionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RemoveActionSetsFromDefinitionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RemoveActionSetsFromDefinitionRequest;
    static equals(a: RemoveActionSetsFromDefinitionRequest | PlainMessage<RemoveActionSetsFromDefinitionRequest> | undefined, b: RemoveActionSetsFromDefinitionRequest | PlainMessage<RemoveActionSetsFromDefinitionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RemoveActionSetsFromDefinitionResponse
 */
export declare class RemoveActionSetsFromDefinitionResponse extends Message<RemoveActionSetsFromDefinitionResponse> {
    /**
     * @generated from field: powermanage.v1.Definition definition = 1;
     */
    definition?: Definition;
    constructor(data?: PartialMessage<RemoveActionSetsFromDefinitionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RemoveActionSetsFromDefinitionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RemoveActionSetsFromDefinitionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RemoveActionSetsFromDefinitionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RemoveActionSetsFromDefinitionResponse;
    static equals(a: RemoveActionSetsFromDefinitionResponse | PlainMessage<RemoveActionSetsFromDefinitionResponse> | undefined, b: RemoveActionSetsFromDefinitionResponse | PlainMessage<RemoveActionSetsFromDefinitionResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.Assignment
 */
export declare class Assignment extends Message<Assignment> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * Source (what is being assigned)
     *
     * @generated from field: powermanage.v1.AssignmentSourceType source_type = 2;
     */
    sourceType: AssignmentSourceType;
    /**
     * @generated from field: string source_id = 3;
     */
    sourceId: string;
    /**
     * Denormalized for display
     *
     * @generated from field: string source_name = 4;
     */
    sourceName: string;
    /**
     * Target (what it's assigned to)
     *
     * @generated from field: powermanage.v1.AssignmentTargetType target_type = 5;
     */
    targetType: AssignmentTargetType;
    /**
     * @generated from field: string target_id = 6;
     */
    targetId: string;
    /**
     * Denormalized for display
     *
     * @generated from field: string target_name = 7;
     */
    targetName: string;
    /**
     * Priority for conflict resolution (higher = wins)
     *
     * @generated from field: int32 priority = 10;
     */
    priority: number;
    /**
     * Assignment state (required, available, absent)
     *
     * @generated from field: powermanage.v1.AssignmentState state = 11;
     */
    state: AssignmentState;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 20;
     */
    createdAt?: Timestamp;
    constructor(data?: PartialMessage<Assignment>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Assignment";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Assignment;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Assignment;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Assignment;
    static equals(a: Assignment | PlainMessage<Assignment> | undefined, b: Assignment | PlainMessage<Assignment> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateAssignmentRequest
 */
export declare class CreateAssignmentRequest extends Message<CreateAssignmentRequest> {
    /**
     * @generated from field: powermanage.v1.AssignmentSourceType source_type = 1;
     */
    sourceType: AssignmentSourceType;
    /**
     * @generated from field: string source_id = 2;
     */
    sourceId: string;
    /**
     * @generated from field: powermanage.v1.AssignmentTargetType target_type = 3;
     */
    targetType: AssignmentTargetType;
    /**
     * @generated from field: string target_id = 4;
     */
    targetId: string;
    /**
     * @generated from field: int32 priority = 5;
     */
    priority: number;
    /**
     * @generated from field: powermanage.v1.AssignmentState state = 6;
     */
    state: AssignmentState;
    constructor(data?: PartialMessage<CreateAssignmentRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateAssignmentRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateAssignmentRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateAssignmentRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateAssignmentRequest;
    static equals(a: CreateAssignmentRequest | PlainMessage<CreateAssignmentRequest> | undefined, b: CreateAssignmentRequest | PlainMessage<CreateAssignmentRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateAssignmentResponse
 */
export declare class CreateAssignmentResponse extends Message<CreateAssignmentResponse> {
    /**
     * @generated from field: powermanage.v1.Assignment assignment = 1;
     */
    assignment?: Assignment;
    constructor(data?: PartialMessage<CreateAssignmentResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateAssignmentResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateAssignmentResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateAssignmentResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateAssignmentResponse;
    static equals(a: CreateAssignmentResponse | PlainMessage<CreateAssignmentResponse> | undefined, b: CreateAssignmentResponse | PlainMessage<CreateAssignmentResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListAssignmentsRequest
 */
export declare class ListAssignmentsRequest extends Message<ListAssignmentsRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * Filter by source
     *
     * @generated from field: optional powermanage.v1.AssignmentSourceType source_type = 3;
     */
    sourceType?: AssignmentSourceType;
    /**
     * @generated from field: optional string source_id = 4;
     */
    sourceId?: string;
    /**
     * Filter by target
     *
     * @generated from field: optional powermanage.v1.AssignmentTargetType target_type = 5;
     */
    targetType?: AssignmentTargetType;
    /**
     * @generated from field: optional string target_id = 6;
     */
    targetId?: string;
    constructor(data?: PartialMessage<ListAssignmentsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListAssignmentsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListAssignmentsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListAssignmentsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListAssignmentsRequest;
    static equals(a: ListAssignmentsRequest | PlainMessage<ListAssignmentsRequest> | undefined, b: ListAssignmentsRequest | PlainMessage<ListAssignmentsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListAssignmentsResponse
 */
export declare class ListAssignmentsResponse extends Message<ListAssignmentsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.Assignment assignments = 1;
     */
    assignments: Assignment[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListAssignmentsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListAssignmentsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListAssignmentsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListAssignmentsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListAssignmentsResponse;
    static equals(a: ListAssignmentsResponse | PlainMessage<ListAssignmentsResponse> | undefined, b: ListAssignmentsResponse | PlainMessage<ListAssignmentsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteAssignmentRequest
 */
export declare class DeleteAssignmentRequest extends Message<DeleteAssignmentRequest> {
    /**
     * @generated from field: string assignment_id = 1;
     */
    assignmentId: string;
    constructor(data?: PartialMessage<DeleteAssignmentRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteAssignmentRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteAssignmentRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteAssignmentRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteAssignmentRequest;
    static equals(a: DeleteAssignmentRequest | PlainMessage<DeleteAssignmentRequest> | undefined, b: DeleteAssignmentRequest | PlainMessage<DeleteAssignmentRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteAssignmentResponse
 */
export declare class DeleteAssignmentResponse extends Message<DeleteAssignmentResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteAssignmentResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteAssignmentResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteAssignmentResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteAssignmentResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteAssignmentResponse;
    static equals(a: DeleteAssignmentResponse | PlainMessage<DeleteAssignmentResponse> | undefined, b: DeleteAssignmentResponse | PlainMessage<DeleteAssignmentResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetEffectiveActionsRequest
 */
export declare class GetEffectiveActionsRequest extends Message<GetEffectiveActionsRequest> {
    /**
     * @generated from field: string device_id = 1;
     */
    deviceId: string;
    constructor(data?: PartialMessage<GetEffectiveActionsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetEffectiveActionsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetEffectiveActionsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetEffectiveActionsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetEffectiveActionsRequest;
    static equals(a: GetEffectiveActionsRequest | PlainMessage<GetEffectiveActionsRequest> | undefined, b: GetEffectiveActionsRequest | PlainMessage<GetEffectiveActionsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetEffectiveActionsResponse
 */
export declare class GetEffectiveActionsResponse extends Message<GetEffectiveActionsResponse> {
    /**
     * Final list of actions for the device
     *
     * @generated from field: repeated powermanage.v1.EffectiveAction effective_actions = 1;
     */
    effectiveActions: EffectiveAction[];
    constructor(data?: PartialMessage<GetEffectiveActionsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetEffectiveActionsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetEffectiveActionsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetEffectiveActionsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetEffectiveActionsResponse;
    static equals(a: GetEffectiveActionsResponse | PlainMessage<GetEffectiveActionsResponse> | undefined, b: GetEffectiveActionsResponse | PlainMessage<GetEffectiveActionsResponse> | undefined): boolean;
}
/**
 * An action with its assignment chain
 *
 * @generated from message powermanage.v1.EffectiveAction
 */
export declare class EffectiveAction extends Message<EffectiveAction> {
    /**
     * The action to apply
     *
     * @generated from field: powermanage.v1.Action action = 1;
     */
    action?: Action;
    /**
     * How this action was assigned (for debugging/display)
     *
     * @generated from field: repeated powermanage.v1.AssignmentPath assignment_paths = 2;
     */
    assignmentPaths: AssignmentPath[];
    /**
     * Resolved state for this action (based on highest priority assignment)
     *
     * @generated from field: powermanage.v1.AssignmentState state = 3;
     */
    state: AssignmentState;
    constructor(data?: PartialMessage<EffectiveAction>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.EffectiveAction";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): EffectiveAction;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): EffectiveAction;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): EffectiveAction;
    static equals(a: EffectiveAction | PlainMessage<EffectiveAction> | undefined, b: EffectiveAction | PlainMessage<EffectiveAction> | undefined): boolean;
}
/**
 * Shows the assignment chain for an action
 *
 * @generated from message powermanage.v1.AssignmentPath
 */
export declare class AssignmentPath extends Message<AssignmentPath> {
    /**
     * e.g., "Definition: Web Server" -> "ActionSet: Security" -> "Action: Install nginx"
     *
     * @generated from field: repeated string path_elements = 1;
     */
    pathElements: string[];
    /**
     * @generated from field: powermanage.v1.Assignment assignment = 2;
     */
    assignment?: Assignment;
    constructor(data?: PartialMessage<AssignmentPath>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.AssignmentPath";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AssignmentPath;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AssignmentPath;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AssignmentPath;
    static equals(a: AssignmentPath | PlainMessage<AssignmentPath> | undefined, b: AssignmentPath | PlainMessage<AssignmentPath> | undefined): boolean;
}
//# sourceMappingURL=action_management_pb.d.ts.map