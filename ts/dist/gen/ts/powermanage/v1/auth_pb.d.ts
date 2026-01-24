import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
/**
 * User roles
 *
 * @generated from enum powermanage.v1.UserRole
 */
export declare enum UserRole {
    /**
     * @generated from enum value: USER_ROLE_UNSPECIFIED = 0;
     */
    UNSPECIFIED = 0,
    /**
     * Can view, limited actions
     *
     * @generated from enum value: USER_ROLE_USER = 1;
     */
    USER = 1,
    /**
     * Full access
     *
     * @generated from enum value: USER_ROLE_ADMIN = 2;
     */
    ADMIN = 2
}
/**
 * @generated from message powermanage.v1.BeginRegistrationRequest
 */
export declare class BeginRegistrationRequest extends Message<BeginRegistrationRequest> {
    /**
     * Registration code provided by admin
     *
     * @generated from field: string registration_code = 1;
     */
    registrationCode: string;
    constructor(data?: PartialMessage<BeginRegistrationRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.BeginRegistrationRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): BeginRegistrationRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): BeginRegistrationRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): BeginRegistrationRequest;
    static equals(a: BeginRegistrationRequest | PlainMessage<BeginRegistrationRequest> | undefined, b: BeginRegistrationRequest | PlainMessage<BeginRegistrationRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.BeginRegistrationResponse
 */
export declare class BeginRegistrationResponse extends Message<BeginRegistrationResponse> {
    /**
     * WebAuthn options as JSON (to be parsed by browser)
     *
     * @generated from field: string options_json = 1;
     */
    optionsJson: string;
    /**
     * Session ID for finishing registration
     *
     * @generated from field: string session_id = 2;
     */
    sessionId: string;
    /**
     * Username being registered (from registration code)
     *
     * @generated from field: string username = 3;
     */
    username: string;
    constructor(data?: PartialMessage<BeginRegistrationResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.BeginRegistrationResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): BeginRegistrationResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): BeginRegistrationResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): BeginRegistrationResponse;
    static equals(a: BeginRegistrationResponse | PlainMessage<BeginRegistrationResponse> | undefined, b: BeginRegistrationResponse | PlainMessage<BeginRegistrationResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.FinishRegistrationRequest
 */
export declare class FinishRegistrationRequest extends Message<FinishRegistrationRequest> {
    /**
     * Session ID from BeginRegistration
     *
     * @generated from field: string session_id = 1;
     */
    sessionId: string;
    /**
     * Attestation response from browser as JSON
     *
     * @generated from field: string attestation_json = 2;
     */
    attestationJson: string;
    constructor(data?: PartialMessage<FinishRegistrationRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.FinishRegistrationRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): FinishRegistrationRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): FinishRegistrationRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): FinishRegistrationRequest;
    static equals(a: FinishRegistrationRequest | PlainMessage<FinishRegistrationRequest> | undefined, b: FinishRegistrationRequest | PlainMessage<FinishRegistrationRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.FinishRegistrationResponse
 */
export declare class FinishRegistrationResponse extends Message<FinishRegistrationResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    /**
     * @generated from field: optional string error_message = 2;
     */
    errorMessage?: string;
    /**
     * User info on success
     *
     * @generated from field: optional powermanage.v1.User user = 3;
     */
    user?: User;
    constructor(data?: PartialMessage<FinishRegistrationResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.FinishRegistrationResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): FinishRegistrationResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): FinishRegistrationResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): FinishRegistrationResponse;
    static equals(a: FinishRegistrationResponse | PlainMessage<FinishRegistrationResponse> | undefined, b: FinishRegistrationResponse | PlainMessage<FinishRegistrationResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.BeginLoginRequest
 */
export declare class BeginLoginRequest extends Message<BeginLoginRequest> {
    /**
     * Username is optional for discoverable credentials
     *
     * @generated from field: optional string username = 1;
     */
    username?: string;
    constructor(data?: PartialMessage<BeginLoginRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.BeginLoginRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): BeginLoginRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): BeginLoginRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): BeginLoginRequest;
    static equals(a: BeginLoginRequest | PlainMessage<BeginLoginRequest> | undefined, b: BeginLoginRequest | PlainMessage<BeginLoginRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.BeginLoginResponse
 */
export declare class BeginLoginResponse extends Message<BeginLoginResponse> {
    /**
     * WebAuthn options as JSON
     *
     * @generated from field: string options_json = 1;
     */
    optionsJson: string;
    /**
     * Session ID for finishing login
     *
     * @generated from field: string session_id = 2;
     */
    sessionId: string;
    constructor(data?: PartialMessage<BeginLoginResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.BeginLoginResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): BeginLoginResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): BeginLoginResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): BeginLoginResponse;
    static equals(a: BeginLoginResponse | PlainMessage<BeginLoginResponse> | undefined, b: BeginLoginResponse | PlainMessage<BeginLoginResponse> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.FinishLoginRequest
 */
export declare class FinishLoginRequest extends Message<FinishLoginRequest> {
    /**
     * Session ID from BeginLogin
     *
     * @generated from field: string session_id = 1;
     */
    sessionId: string;
    /**
     * Assertion response from browser as JSON
     *
     * @generated from field: string assertion_json = 2;
     */
    assertionJson: string;
    constructor(data?: PartialMessage<FinishLoginRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.FinishLoginRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): FinishLoginRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): FinishLoginRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): FinishLoginRequest;
    static equals(a: FinishLoginRequest | PlainMessage<FinishLoginRequest> | undefined, b: FinishLoginRequest | PlainMessage<FinishLoginRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.FinishLoginResponse
 */
export declare class FinishLoginResponse extends Message<FinishLoginResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    /**
     * @generated from field: optional string error_message = 2;
     */
    errorMessage?: string;
    /**
     * Session info on success
     *
     * @generated from field: optional powermanage.v1.Session session = 3;
     */
    session?: Session;
    constructor(data?: PartialMessage<FinishLoginResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.FinishLoginResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): FinishLoginResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): FinishLoginResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): FinishLoginResponse;
    static equals(a: FinishLoginResponse | PlainMessage<FinishLoginResponse> | undefined, b: FinishLoginResponse | PlainMessage<FinishLoginResponse> | undefined): boolean;
}
/**
 * Empty - uses session cookie
 *
 * @generated from message powermanage.v1.LogoutRequest
 */
export declare class LogoutRequest extends Message<LogoutRequest> {
    constructor(data?: PartialMessage<LogoutRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.LogoutRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): LogoutRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): LogoutRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): LogoutRequest;
    static equals(a: LogoutRequest | PlainMessage<LogoutRequest> | undefined, b: LogoutRequest | PlainMessage<LogoutRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.LogoutResponse
 */
export declare class LogoutResponse extends Message<LogoutResponse> {
    /**
     * @generated from field: bool success = 1;
     */
    success: boolean;
    constructor(data?: PartialMessage<LogoutResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.LogoutResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): LogoutResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): LogoutResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): LogoutResponse;
    static equals(a: LogoutResponse | PlainMessage<LogoutResponse> | undefined, b: LogoutResponse | PlainMessage<LogoutResponse> | undefined): boolean;
}
/**
 * Empty - uses session cookie
 *
 * @generated from message powermanage.v1.GetSessionRequest
 */
export declare class GetSessionRequest extends Message<GetSessionRequest> {
    constructor(data?: PartialMessage<GetSessionRequest>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetSessionRequest";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetSessionRequest;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetSessionRequest;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetSessionRequest;
    static equals(a: GetSessionRequest | PlainMessage<GetSessionRequest> | undefined, b: GetSessionRequest | PlainMessage<GetSessionRequest> | undefined): boolean;
}
/**
 * @generated from message powermanage.v1.GetSessionResponse
 */
export declare class GetSessionResponse extends Message<GetSessionResponse> {
    /**
     * @generated from field: bool authenticated = 1;
     */
    authenticated: boolean;
    /**
     * @generated from field: optional powermanage.v1.Session session = 2;
     */
    session?: Session;
    constructor(data?: PartialMessage<GetSessionResponse>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.GetSessionResponse";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetSessionResponse;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetSessionResponse;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetSessionResponse;
    static equals(a: GetSessionResponse | PlainMessage<GetSessionResponse> | undefined, b: GetSessionResponse | PlainMessage<GetSessionResponse> | undefined): boolean;
}
/**
 * User information
 *
 * @generated from message powermanage.v1.User
 */
export declare class User extends Message<User> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: string username = 2;
     */
    username: string;
    /**
     * @generated from field: string display_name = 3;
     */
    displayName: string;
    /**
     * @generated from field: powermanage.v1.UserRole role = 4;
     */
    role: UserRole;
    /**
     * Identity provider (for future OIDC/SAML support)
     *
     * "local", "oidc:google", "saml:okta"
     *
     * @generated from field: string identity_provider = 5;
     */
    identityProvider: string;
    /**
     * External ID from identity provider (sub claim, etc.)
     *
     * @generated from field: optional string external_id = 6;
     */
    externalId?: string;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 7;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: optional google.protobuf.Timestamp last_login_at = 8;
     */
    lastLoginAt?: Timestamp;
    constructor(data?: PartialMessage<User>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.User";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): User;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): User;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): User;
    static equals(a: User | PlainMessage<User> | undefined, b: User | PlainMessage<User> | undefined): boolean;
}
/**
 * Session information
 *
 * @generated from message powermanage.v1.Session
 */
export declare class Session extends Message<Session> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * @generated from field: powermanage.v1.User user = 2;
     */
    user?: User;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 3;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp expires_at = 4;
     */
    expiresAt?: Timestamp;
    constructor(data?: PartialMessage<Session>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.Session";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Session;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Session;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Session;
    static equals(a: Session | PlainMessage<Session> | undefined, b: Session | PlainMessage<Session> | undefined): boolean;
}
/**
 * WebAuthn credential info (for listing/revocation)
 *
 * @generated from message powermanage.v1.WebAuthnCredential
 */
export declare class WebAuthnCredential extends Message<WebAuthnCredential> {
    /**
     * @generated from field: string id = 1;
     */
    id: string;
    /**
     * User-friendly name
     *
     * @generated from field: string name = 2;
     */
    name: string;
    /**
     * @generated from field: google.protobuf.Timestamp created_at = 3;
     */
    createdAt?: Timestamp;
    /**
     * @generated from field: google.protobuf.Timestamp last_used_at = 4;
     */
    lastUsedAt?: Timestamp;
    /**
     * AAGUID can identify the authenticator type
     *
     * @generated from field: optional string aaguid = 5;
     */
    aaguid?: string;
    constructor(data?: PartialMessage<WebAuthnCredential>);
    static readonly runtime: typeof proto3;
    static readonly typeName = "powermanage.v1.WebAuthnCredential";
    static readonly fields: FieldList;
    static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): WebAuthnCredential;
    static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): WebAuthnCredential;
    static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): WebAuthnCredential;
    static equals(a: WebAuthnCredential | PlainMessage<WebAuthnCredential> | undefined, b: WebAuthnCredential | PlainMessage<WebAuthnCredential> | undefined): boolean;
}
//# sourceMappingURL=auth_pb.d.ts.map