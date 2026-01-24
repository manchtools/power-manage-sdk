import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { User, UserRole, WebAuthnCredential } from "./auth_pb.js";
/**
 * @generated from message powermanage.v1.CreateUserRequest
 */
export declare class CreateUserRequest extends Message<CreateUserRequest> {
    /**
     * @generated from field: string username = 1;
     */
    username: string;
    /**
     * @generated from field: string display_name = 2;
     */
    displayName: string;
    /**
     * @generated from field: powermanage.v1.UserRole role = 3;
     */
    role: UserRole;
    /**
     * If true, also generate a registration code
     *
     * @generated from field: bool generate_registration_code = 4;
     */
    generateRegistrationCode: boolean;
    constructor(data?: PartialMessage<CreateUserRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateUserRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateUserRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateUserRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateUserRequest;
    static equals(a: CreateUserRequest | PlainMessage<CreateUserRequest> | undefined, b: CreateUserRequest | PlainMessage<CreateUserRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateUserResponse
 */
export declare class CreateUserResponse extends Message<CreateUserResponse> {
    /**
     * @generated from field: powermanage.v1.User user = 1;
     */
    user?: User;
    /**
     * Registration code if requested
     *
     * @generated from field: optional powermanage.v1.RegistrationCode registration_code = 2;
     */
    registrationCode?: RegistrationCode;
    constructor(data?: PartialMessage<CreateUserResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateUserResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateUserResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateUserResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateUserResponse;
    static equals(a: CreateUserResponse | PlainMessage<CreateUserResponse> | undefined, b: CreateUserResponse | PlainMessage<CreateUserResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetUserRequest
 */
export declare class GetUserRequest extends Message<GetUserRequest> {
    /**
     * @generated from field: string user_id = 1;
     */
    userId: string;
    constructor(data?: PartialMessage<GetUserRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetUserRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetUserRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetUserRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetUserRequest;
    static equals(a: GetUserRequest | PlainMessage<GetUserRequest> | undefined, b: GetUserRequest | PlainMessage<GetUserRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetUserResponse
 */
export declare class GetUserResponse extends Message<GetUserResponse> {
    /**
     * @generated from field: powermanage.v1.User user = 1;
     */
    user?: User;
    constructor(data?: PartialMessage<GetUserResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetUserResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetUserResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetUserResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetUserResponse;
    static equals(a: GetUserResponse | PlainMessage<GetUserResponse> | undefined, b: GetUserResponse | PlainMessage<GetUserResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListUsersRequest
 */
export declare class ListUsersRequest extends Message<ListUsersRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * Filter by role
     *
     * @generated from field: optional powermanage.v1.UserRole role_filter = 3;
     */
    roleFilter?: UserRole;
    constructor(data?: PartialMessage<ListUsersRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListUsersRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListUsersRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListUsersRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListUsersRequest;
    static equals(a: ListUsersRequest | PlainMessage<ListUsersRequest> | undefined, b: ListUsersRequest | PlainMessage<ListUsersRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListUsersResponse
 */
export declare class ListUsersResponse extends Message<ListUsersResponse> {
    /**
     * @generated from field: repeated powermanage.v1.User users = 1;
     */
    users: User[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    /**
     * @generated from field: int32 total_count = 3;
     */
    totalCount: number;
    constructor(data?: PartialMessage<ListUsersResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListUsersResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListUsersResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListUsersResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListUsersResponse;
    static equals(a: ListUsersResponse | PlainMessage<ListUsersResponse> | undefined, b: ListUsersResponse | PlainMessage<ListUsersResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateUserRequest
 */
export declare class UpdateUserRequest extends Message<UpdateUserRequest> {
    /**
     * @generated from field: string user_id = 1;
     */
    userId: string;
    /**
     * @generated from field: optional string display_name = 2;
     */
    displayName?: string;
    /**
     * Admin only
     *
     * @generated from field: optional powermanage.v1.UserRole role = 3;
     */
    role?: UserRole;
    constructor(data?: PartialMessage<UpdateUserRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateUserRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateUserRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateUserRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateUserRequest;
    static equals(a: UpdateUserRequest | PlainMessage<UpdateUserRequest> | undefined, b: UpdateUserRequest | PlainMessage<UpdateUserRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.UpdateUserResponse
 */
export declare class UpdateUserResponse extends Message<UpdateUserResponse> {
    /**
     * @generated from field: powermanage.v1.User user = 1;
     */
    user?: User;
    constructor(data?: PartialMessage<UpdateUserResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.UpdateUserResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UpdateUserResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UpdateUserResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UpdateUserResponse;
    static equals(a: UpdateUserResponse | PlainMessage<UpdateUserResponse> | undefined, b: UpdateUserResponse | PlainMessage<UpdateUserResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteUserRequest
 */
export declare class DeleteUserRequest extends Message<DeleteUserRequest> {
    /**
     * @generated from field: string user_id = 1;
     */
    userId: string;
    constructor(data?: PartialMessage<DeleteUserRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteUserRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteUserRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteUserRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteUserRequest;
    static equals(a: DeleteUserRequest | PlainMessage<DeleteUserRequest> | undefined, b: DeleteUserRequest | PlainMessage<DeleteUserRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.DeleteUserResponse
 */
export declare class DeleteUserResponse extends Message<DeleteUserResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<DeleteUserResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.DeleteUserResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): DeleteUserResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): DeleteUserResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): DeleteUserResponse;
    static equals(a: DeleteUserResponse | PlainMessage<DeleteUserResponse> | undefined, b: DeleteUserResponse | PlainMessage<DeleteUserResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RegistrationCode
 */
export declare class RegistrationCode extends Message<RegistrationCode> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * The actual code to give to user
     *
     * @generated from field: string code = 2;
     */
    code: string;
    /**
     * User this code is for
     *
     * @generated from field: string user_id = 3;
     */
    userId: string;
    /**
     * @generated from field: string username = 4;
     */
    username: string;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 5;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp expires_at = 6;
     */
    expiresAt?: Timestamp;
    /**
     * @generated from field: bool used = 7;
     */
    used: boolean;
    /**
     * @generated from field: optional google.protobuf.Timestamp used_at = 8;
     */
    usedAt?: Timestamp;
    constructor(data?: PartialMessage<RegistrationCode>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RegistrationCode";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RegistrationCode;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RegistrationCode;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RegistrationCode;
    static equals(a: RegistrationCode | PlainMessage<RegistrationCode> | undefined, b: RegistrationCode | PlainMessage<RegistrationCode> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateRegistrationCodeRequest
 */
export declare class CreateRegistrationCodeRequest extends Message<CreateRegistrationCodeRequest> {
    /**
     * @generated from field: string user_id = 1;
     */
    userId: string;
    /**
     * Duration in seconds (default 24h)
     *
     * @generated from field: optional int64 expires_in_seconds = 2;
     */
    expiresInSeconds?: bigint;
    constructor(data?: PartialMessage<CreateRegistrationCodeRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateRegistrationCodeRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateRegistrationCodeRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateRegistrationCodeRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateRegistrationCodeRequest;
    static equals(a: CreateRegistrationCodeRequest | PlainMessage<CreateRegistrationCodeRequest> | undefined, b: CreateRegistrationCodeRequest | PlainMessage<CreateRegistrationCodeRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.CreateRegistrationCodeResponse
 */
export declare class CreateRegistrationCodeResponse extends Message<CreateRegistrationCodeResponse> {
    /**
     * @generated from field: powermanage.v1.RegistrationCode registration_code = 1;
     */
    registrationCode?: RegistrationCode;
    constructor(data?: PartialMessage<CreateRegistrationCodeResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.CreateRegistrationCodeResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): CreateRegistrationCodeResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): CreateRegistrationCodeResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): CreateRegistrationCodeResponse;
    static equals(a: CreateRegistrationCodeResponse | PlainMessage<CreateRegistrationCodeResponse> | undefined, b: CreateRegistrationCodeResponse | PlainMessage<CreateRegistrationCodeResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListRegistrationCodesRequest
 */
export declare class ListRegistrationCodesRequest extends Message<ListRegistrationCodesRequest> {
    /**
     * @generated from field: int32 page_size = 1;
     */
    pageSize: number;
    /**
     * @generated from field: string page_token = 2;
     */
    pageToken: string;
    /**
     * Filter by user
     *
     * @generated from field: optional string user_id = 3;
     */
    userId?: string;
    /**
     * Filter by status
     *
     * @generated from field: optional bool include_used = 4;
     */
    includeUsed?: boolean;
    /**
     * @generated from field: optional bool include_expired = 5;
     */
    includeExpired?: boolean;
    constructor(data?: PartialMessage<ListRegistrationCodesRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListRegistrationCodesRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListRegistrationCodesRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListRegistrationCodesRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListRegistrationCodesRequest;
    static equals(a: ListRegistrationCodesRequest | PlainMessage<ListRegistrationCodesRequest> | undefined, b: ListRegistrationCodesRequest | PlainMessage<ListRegistrationCodesRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListRegistrationCodesResponse
 */
export declare class ListRegistrationCodesResponse extends Message<ListRegistrationCodesResponse> {
    /**
     * @generated from field: repeated powermanage.v1.RegistrationCode registration_codes = 1;
     */
    registrationCodes: RegistrationCode[];
    /**
     * @generated from field: string next_page_token = 2;
     */
    nextPageToken: string;
    constructor(data?: PartialMessage<ListRegistrationCodesResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListRegistrationCodesResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListRegistrationCodesResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListRegistrationCodesResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListRegistrationCodesResponse;
    static equals(a: ListRegistrationCodesResponse | PlainMessage<ListRegistrationCodesResponse> | undefined, b: ListRegistrationCodesResponse | PlainMessage<ListRegistrationCodesResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeRegistrationCodeRequest
 */
export declare class RevokeRegistrationCodeRequest extends Message<RevokeRegistrationCodeRequest> {
    /**
     * @generated from field: string code_id = 1;
     */
    codeId: string;
    constructor(data?: PartialMessage<RevokeRegistrationCodeRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeRegistrationCodeRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeRegistrationCodeRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeRegistrationCodeRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeRegistrationCodeRequest;
    static equals(a: RevokeRegistrationCodeRequest | PlainMessage<RevokeRegistrationCodeRequest> | undefined, b: RevokeRegistrationCodeRequest | PlainMessage<RevokeRegistrationCodeRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeRegistrationCodeResponse
 */
export declare class RevokeRegistrationCodeResponse extends Message<RevokeRegistrationCodeResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<RevokeRegistrationCodeResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeRegistrationCodeResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeRegistrationCodeResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeRegistrationCodeResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeRegistrationCodeResponse;
    static equals(a: RevokeRegistrationCodeResponse | PlainMessage<RevokeRegistrationCodeResponse> | undefined, b: RevokeRegistrationCodeResponse | PlainMessage<RevokeRegistrationCodeResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListCredentialsRequest
 */
export declare class ListCredentialsRequest extends Message<ListCredentialsRequest> {
    /**
     * If not set, returns credentials for current user
     *
     * @generated from field: optional string user_id = 1;
     */
    userId?: string;
    constructor(data?: PartialMessage<ListCredentialsRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListCredentialsRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListCredentialsRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListCredentialsRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListCredentialsRequest;
    static equals(a: ListCredentialsRequest | PlainMessage<ListCredentialsRequest> | undefined, b: ListCredentialsRequest | PlainMessage<ListCredentialsRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.ListCredentialsResponse
 */
export declare class ListCredentialsResponse extends Message<ListCredentialsResponse> {
    /**
     * @generated from field: repeated powermanage.v1.WebAuthnCredential credentials = 1;
     */
    credentials: WebAuthnCredential[];
    constructor(data?: PartialMessage<ListCredentialsResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.ListCredentialsResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListCredentialsResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListCredentialsResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListCredentialsResponse;
    static equals(a: ListCredentialsResponse | PlainMessage<ListCredentialsResponse> | undefined, b: ListCredentialsResponse | PlainMessage<ListCredentialsResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeCredentialRequest
 */
export declare class RevokeCredentialRequest extends Message<RevokeCredentialRequest> {
    /**
     * @generated from field: string credential_id = 1;
     */
    credentialId: string;
    constructor(data?: PartialMessage<RevokeCredentialRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeCredentialRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeCredentialRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeCredentialRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeCredentialRequest;
    static equals(a: RevokeCredentialRequest | PlainMessage<RevokeCredentialRequest> | undefined, b: RevokeCredentialRequest | PlainMessage<RevokeCredentialRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RevokeCredentialResponse
 */
export declare class RevokeCredentialResponse extends Message<RevokeCredentialResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<RevokeCredentialResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RevokeCredentialResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RevokeCredentialResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RevokeCredentialResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RevokeCredentialResponse;
    static equals(a: RevokeCredentialResponse | PlainMessage<RevokeCredentialResponse> | undefined, b: RevokeCredentialResponse | PlainMessage<RevokeCredentialResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RenameCredentialRequest
 */
export declare class RenameCredentialRequest extends Message<RenameCredentialRequest> {
    /**
     * @generated from field: string credential_id = 1;
     */
    credentialId: string;
    /**
     * @generated from field: string new_name = 2;
     */
    newName: string;
    constructor(data?: PartialMessage<RenameCredentialRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RenameCredentialRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RenameCredentialRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RenameCredentialRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RenameCredentialRequest;
    static equals(a: RenameCredentialRequest | PlainMessage<RenameCredentialRequest> | undefined, b: RenameCredentialRequest | PlainMessage<RenameCredentialRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.RenameCredentialResponse
 */
export declare class RenameCredentialResponse extends Message<RenameCredentialResponse> {
    /**
     * @generated from field: powermanage.v1.WebAuthnCredential credential = 1;
     */
    credential?: WebAuthnCredential;
    constructor(data?: PartialMessage<RenameCredentialResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.RenameCredentialResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): RenameCredentialResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): RenameCredentialResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): RenameCredentialResponse;
    static equals(a: RenameCredentialResponse | PlainMessage<RenameCredentialResponse> | undefined, b: RenameCredentialResponse | PlainMessage<RenameCredentialResponse> | undefined): boolean;
}
//# sourceMappingURL=users_pb.d.ts.map