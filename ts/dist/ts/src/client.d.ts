import { type Client } from '@connectrpc/connect';
import { AuthService } from '../../gen/ts/powermanage/v1/auth_connect.js';
import { UserService } from '../../gen/ts/powermanage/v1/users_connect.js';
import { DeviceService } from '../../gen/ts/powermanage/v1/devices_connect.js';
import { DeviceGroupService } from '../../gen/ts/powermanage/v1/device_groups_connect.js';
import { ActionManagementService, ActionSetService, DefinitionService, AssignmentService } from '../../gen/ts/powermanage/v1/action_management_connect.js';
export interface PowerManageClientOptions {
    /** Server URL. If not provided, uses ConfigStore. */
    serverUrl?: string;
    /** Whether to include credentials (cookies) in requests. Default: true */
    credentials?: boolean;
}
/**
 * Power Manage API client.
 * Provides typed access to all server APIs.
 */
export declare class PowerManageClient {
    private transport;
    readonly auth: Client<typeof AuthService>;
    readonly users: Client<typeof UserService>;
    readonly devices: Client<typeof DeviceService>;
    readonly deviceGroups: Client<typeof DeviceGroupService>;
    readonly actions: Client<typeof ActionManagementService>;
    readonly actionSets: Client<typeof ActionSetService>;
    readonly definitions: Client<typeof DefinitionService>;
    readonly assignments: Client<typeof AssignmentService>;
    constructor(options?: PowerManageClientOptions);
    /**
     * Begin WebAuthn registration with a registration code.
     */
    beginRegistration(registrationCode: string): Promise<import("../../gen/ts/powermanage/v1/auth_pb.js").BeginRegistrationResponse>;
    /**
     * Complete WebAuthn registration.
     */
    finishRegistration(sessionId: string, optionsJson: string): Promise<import("../../gen/ts/powermanage/v1/auth_pb.js").FinishRegistrationResponse>;
    /**
     * Begin WebAuthn login.
     */
    beginLogin(username?: string): Promise<import("../../gen/ts/powermanage/v1/auth_pb.js").BeginLoginResponse>;
    /**
     * Complete WebAuthn login.
     */
    finishLogin(sessionId: string, optionsJson: string, useConditionalUI?: boolean): Promise<import("../../gen/ts/powermanage/v1/auth_pb.js").FinishLoginResponse>;
    /**
     * Logout and clear session.
     */
    logout(): Promise<void>;
    /**
     * Get current session from server.
     */
    getSession(): Promise<import("../../gen/ts/powermanage/v1/auth_pb.js").GetSessionResponse>;
    /**
     * Check if server is reachable.
     */
    healthCheck(): Promise<boolean>;
}
/**
 * Get or create the global PowerManageClient instance.
 * Creates a new instance if server URL changes.
 */
export declare function getClient(options?: PowerManageClientOptions): PowerManageClient;
/**
 * Reset the client instance (e.g., when server URL changes).
 */
export declare function resetClient(): void;
//# sourceMappingURL=client.d.ts.map