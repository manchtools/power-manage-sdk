import { BeginLoginRequest, BeginLoginResponse, BeginRegistrationRequest, BeginRegistrationResponse, FinishLoginRequest, FinishLoginResponse, FinishRegistrationRequest, FinishRegistrationResponse, GetSessionRequest, GetSessionResponse, LogoutRequest, LogoutResponse } from "./auth_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.AuthService
 */
export declare const AuthService: {
    readonly typeName: "powermanage.v1.AuthService";
    readonly methods: {
        /**
         * Begin passkey registration (requires registration code)
         *
         * @generated from rpc powermanage.v1.AuthService.BeginRegistration
         */
        readonly beginRegistration: {
            readonly name: "BeginRegistration";
            readonly I: typeof BeginRegistrationRequest;
            readonly O: typeof BeginRegistrationResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Complete passkey registration
         *
         * @generated from rpc powermanage.v1.AuthService.FinishRegistration
         */
        readonly finishRegistration: {
            readonly name: "FinishRegistration";
            readonly I: typeof FinishRegistrationRequest;
            readonly O: typeof FinishRegistrationResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Begin passkey login
         *
         * @generated from rpc powermanage.v1.AuthService.BeginLogin
         */
        readonly beginLogin: {
            readonly name: "BeginLogin";
            readonly I: typeof BeginLoginRequest;
            readonly O: typeof BeginLoginResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Complete passkey login
         *
         * @generated from rpc powermanage.v1.AuthService.FinishLogin
         */
        readonly finishLogin: {
            readonly name: "FinishLogin";
            readonly I: typeof FinishLoginRequest;
            readonly O: typeof FinishLoginResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Logout (invalidate session)
         *
         * @generated from rpc powermanage.v1.AuthService.Logout
         */
        readonly logout: {
            readonly name: "Logout";
            readonly I: typeof LogoutRequest;
            readonly O: typeof LogoutResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get current session info
         *
         * @generated from rpc powermanage.v1.AuthService.GetSession
         */
        readonly getSession: {
            readonly name: "GetSession";
            readonly I: typeof GetSessionRequest;
            readonly O: typeof GetSessionResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=auth_connect.d.ts.map