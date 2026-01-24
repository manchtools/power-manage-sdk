import { CreateRegistrationTokenRequest, CreateRegistrationTokenResponse, DeleteDeviceRequest, DeleteDeviceResponse, GetDeviceHistoryRequest, GetDeviceHistoryResponse, GetDeviceRequest, GetDeviceResponse, ListDevicesRequest, ListDevicesResponse, ListRegistrationTokensRequest, ListRegistrationTokensResponse, RevokeRegistrationTokenRequest, RevokeRegistrationTokenResponse, UpdateDeviceRequest, UpdateDeviceResponse } from "./devices_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.DeviceService
 */
export declare const DeviceService: {
    readonly typeName: "powermanage.v1.DeviceService";
    readonly methods: {
        /**
         * List all devices
         *
         * @generated from rpc powermanage.v1.DeviceService.ListDevices
         */
        readonly listDevices: {
            readonly name: "ListDevices";
            readonly I: typeof ListDevicesRequest;
            readonly O: typeof ListDevicesResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get device by ID
         *
         * @generated from rpc powermanage.v1.DeviceService.GetDevice
         */
        readonly getDevice: {
            readonly name: "GetDevice";
            readonly I: typeof GetDeviceRequest;
            readonly O: typeof GetDeviceResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update device metadata (labels, display name)
         *
         * @generated from rpc powermanage.v1.DeviceService.UpdateDevice
         */
        readonly updateDevice: {
            readonly name: "UpdateDevice";
            readonly I: typeof UpdateDeviceRequest;
            readonly O: typeof UpdateDeviceResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete device (revokes certificate)
         *
         * @generated from rpc powermanage.v1.DeviceService.DeleteDevice
         */
        readonly deleteDevice: {
            readonly name: "DeleteDevice";
            readonly I: typeof DeleteDeviceRequest;
            readonly O: typeof DeleteDeviceResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Generate registration token for agent enrollment
         *
         * @generated from rpc powermanage.v1.DeviceService.CreateRegistrationToken
         */
        readonly createRegistrationToken: {
            readonly name: "CreateRegistrationToken";
            readonly I: typeof CreateRegistrationTokenRequest;
            readonly O: typeof CreateRegistrationTokenResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List registration tokens
         *
         * @generated from rpc powermanage.v1.DeviceService.ListRegistrationTokens
         */
        readonly listRegistrationTokens: {
            readonly name: "ListRegistrationTokens";
            readonly I: typeof ListRegistrationTokensRequest;
            readonly O: typeof ListRegistrationTokensResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Revoke a registration token
         *
         * @generated from rpc powermanage.v1.DeviceService.RevokeRegistrationToken
         */
        readonly revokeRegistrationToken: {
            readonly name: "RevokeRegistrationToken";
            readonly I: typeof RevokeRegistrationTokenRequest;
            readonly O: typeof RevokeRegistrationTokenResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get device's action execution history
         *
         * @generated from rpc powermanage.v1.DeviceService.GetDeviceHistory
         */
        readonly getDeviceHistory: {
            readonly name: "GetDeviceHistory";
            readonly I: typeof GetDeviceHistoryRequest;
            readonly O: typeof GetDeviceHistoryResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=devices_connect.d.ts.map