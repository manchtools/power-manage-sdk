import { CreateRegistrationCodeRequest, CreateRegistrationCodeResponse, CreateUserRequest, CreateUserResponse, DeleteUserRequest, DeleteUserResponse, GetUserRequest, GetUserResponse, ListCredentialsRequest, ListCredentialsResponse, ListRegistrationCodesRequest, ListRegistrationCodesResponse, ListUsersRequest, ListUsersResponse, RenameCredentialRequest, RenameCredentialResponse, RevokeCredentialRequest, RevokeCredentialResponse, RevokeRegistrationCodeRequest, RevokeRegistrationCodeResponse, UpdateUserRequest, UpdateUserResponse } from "./users_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.UserService
 */
export declare const UserService: {
    readonly typeName: "powermanage.v1.UserService";
    readonly methods: {
        /**
         * Create a new user (admin only)
         *
         * @generated from rpc powermanage.v1.UserService.CreateUser
         */
        readonly createUser: {
            readonly name: "CreateUser";
            readonly I: typeof CreateUserRequest;
            readonly O: typeof CreateUserResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get user by ID
         *
         * @generated from rpc powermanage.v1.UserService.GetUser
         */
        readonly getUser: {
            readonly name: "GetUser";
            readonly I: typeof GetUserRequest;
            readonly O: typeof GetUserResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List users with pagination
         *
         * @generated from rpc powermanage.v1.UserService.ListUsers
         */
        readonly listUsers: {
            readonly name: "ListUsers";
            readonly I: typeof ListUsersRequest;
            readonly O: typeof ListUsersResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update user (admin only, or self for display_name)
         *
         * @generated from rpc powermanage.v1.UserService.UpdateUser
         */
        readonly updateUser: {
            readonly name: "UpdateUser";
            readonly I: typeof UpdateUserRequest;
            readonly O: typeof UpdateUserResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete user (admin only)
         *
         * @generated from rpc powermanage.v1.UserService.DeleteUser
         */
        readonly deleteUser: {
            readonly name: "DeleteUser";
            readonly I: typeof DeleteUserRequest;
            readonly O: typeof DeleteUserResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Generate registration code for passkey enrollment
         *
         * @generated from rpc powermanage.v1.UserService.CreateRegistrationCode
         */
        readonly createRegistrationCode: {
            readonly name: "CreateRegistrationCode";
            readonly I: typeof CreateRegistrationCodeRequest;
            readonly O: typeof CreateRegistrationCodeResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List registration codes
         *
         * @generated from rpc powermanage.v1.UserService.ListRegistrationCodes
         */
        readonly listRegistrationCodes: {
            readonly name: "ListRegistrationCodes";
            readonly I: typeof ListRegistrationCodesRequest;
            readonly O: typeof ListRegistrationCodesResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Revoke a registration code
         *
         * @generated from rpc powermanage.v1.UserService.RevokeRegistrationCode
         */
        readonly revokeRegistrationCode: {
            readonly name: "RevokeRegistrationCode";
            readonly I: typeof RevokeRegistrationCodeRequest;
            readonly O: typeof RevokeRegistrationCodeResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List user's WebAuthn credentials
         *
         * @generated from rpc powermanage.v1.UserService.ListCredentials
         */
        readonly listCredentials: {
            readonly name: "ListCredentials";
            readonly I: typeof ListCredentialsRequest;
            readonly O: typeof ListCredentialsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Revoke a WebAuthn credential
         *
         * @generated from rpc powermanage.v1.UserService.RevokeCredential
         */
        readonly revokeCredential: {
            readonly name: "RevokeCredential";
            readonly I: typeof RevokeCredentialRequest;
            readonly O: typeof RevokeCredentialResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Rename a WebAuthn credential
         *
         * @generated from rpc powermanage.v1.UserService.RenameCredential
         */
        readonly renameCredential: {
            readonly name: "RenameCredential";
            readonly I: typeof RenameCredentialRequest;
            readonly O: typeof RenameCredentialResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=users_connect.d.ts.map