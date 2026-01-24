import { CreateDeviceGroupRequest, CreateDeviceGroupResponse, DeleteDeviceGroupRequest, DeleteDeviceGroupResponse, GetDeviceGroupMembersRequest, GetDeviceGroupMembersResponse, GetDeviceGroupRequest, GetDeviceGroupResponse, ListDeviceGroupsRequest, ListDeviceGroupsResponse, PreviewDeviceGroupRequest, PreviewDeviceGroupResponse, UpdateDeviceGroupRequest, UpdateDeviceGroupResponse } from "./device_groups_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.DeviceGroupService
 */
export declare const DeviceGroupService: {
    readonly typeName: "powermanage.v1.DeviceGroupService";
    readonly methods: {
        /**
         * Create a new device group
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.CreateDeviceGroup
         */
        readonly createDeviceGroup: {
            readonly name: "CreateDeviceGroup";
            readonly I: typeof CreateDeviceGroupRequest;
            readonly O: typeof CreateDeviceGroupResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get device group by ID
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.GetDeviceGroup
         */
        readonly getDeviceGroup: {
            readonly name: "GetDeviceGroup";
            readonly I: typeof GetDeviceGroupRequest;
            readonly O: typeof GetDeviceGroupResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List device groups
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.ListDeviceGroups
         */
        readonly listDeviceGroups: {
            readonly name: "ListDeviceGroups";
            readonly I: typeof ListDeviceGroupsRequest;
            readonly O: typeof ListDeviceGroupsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update device group
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.UpdateDeviceGroup
         */
        readonly updateDeviceGroup: {
            readonly name: "UpdateDeviceGroup";
            readonly I: typeof UpdateDeviceGroupRequest;
            readonly O: typeof UpdateDeviceGroupResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete device group
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.DeleteDeviceGroup
         */
        readonly deleteDeviceGroup: {
            readonly name: "DeleteDeviceGroup";
            readonly I: typeof DeleteDeviceGroupRequest;
            readonly O: typeof DeleteDeviceGroupResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Preview which devices match a query (without creating group)
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.PreviewDeviceGroup
         */
        readonly previewDeviceGroup: {
            readonly name: "PreviewDeviceGroup";
            readonly I: typeof PreviewDeviceGroupRequest;
            readonly O: typeof PreviewDeviceGroupResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get current members of a group
         *
         * @generated from rpc powermanage.v1.DeviceGroupService.GetDeviceGroupMembers
         */
        readonly getDeviceGroupMembers: {
            readonly name: "GetDeviceGroupMembers";
            readonly I: typeof GetDeviceGroupMembersRequest;
            readonly O: typeof GetDeviceGroupMembersResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=device_groups_connect.d.ts.map