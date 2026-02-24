// Power Manage API Client.
// Plain TypeScript — no framework dependencies.
// Dependencies (auth store, config) are injected via ClientOptions.

import { createClient, Code, ConnectError } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { create } from '@bufbuild/protobuf';

import {
	ControlService,
	LoginRequestSchema,
	RefreshTokenRequestSchema,
	LogoutRequestSchema,
	GetCurrentUserRequestSchema,
	CreateUserRequestSchema,
	GetUserRequestSchema,
	ListUsersRequestSchema,
	UpdateUserEmailRequestSchema,
	UpdateUserPasswordRequestSchema,
	SetUserDisabledRequestSchema,
	UpdateUserProfileRequestSchema,
	DeleteUserRequestSchema,
	ListDevicesRequestSchema,
	GetDeviceRequestSchema,
	SetDeviceLabelRequestSchema,
	RemoveDeviceLabelRequestSchema,
	AssignDeviceRequestSchema,
	UnassignDeviceRequestSchema,
	DeleteDeviceRequestSchema,
	SetDeviceSyncIntervalRequestSchema,
	CreateTokenRequestSchema,
	GetTokenRequestSchema,
	ListTokensRequestSchema,
	RenameTokenRequestSchema,
	SetTokenDisabledRequestSchema,
	DeleteTokenRequestSchema,
	// Actions (renamed from definitions)
	CreateActionRequestSchema,
	GetActionRequestSchema,
	ListActionsRequestSchema,
	RenameActionRequestSchema,
	UpdateActionDescriptionRequestSchema,
	UpdateActionParamsRequestSchema,
	DeleteActionRequestSchema,
	// Action Sets
	CreateActionSetRequestSchema,
	GetActionSetRequestSchema,
	ListActionSetsRequestSchema,
	RenameActionSetRequestSchema,
	UpdateActionSetDescriptionRequestSchema,
	DeleteActionSetRequestSchema,
	AddActionToSetRequestSchema,
	RemoveActionFromSetRequestSchema,
	ReorderActionInSetRequestSchema,
	// Definitions (collection of action sets)
	CreateDefinitionRequestSchema,
	GetDefinitionRequestSchema,
	ListDefinitionsRequestSchema,
	RenameDefinitionRequestSchema,
	UpdateDefinitionDescriptionRequestSchema,
	DeleteDefinitionRequestSchema,
	AddActionSetToDefinitionRequestSchema,
	RemoveActionSetFromDefinitionRequestSchema,
	ReorderActionSetInDefinitionRequestSchema,
	// Device Groups
	CreateDeviceGroupRequestSchema,
	GetDeviceGroupRequestSchema,
	ListDeviceGroupsRequestSchema,
	RenameDeviceGroupRequestSchema,
	UpdateDeviceGroupDescriptionRequestSchema,
	UpdateDeviceGroupQueryRequestSchema,
	DeleteDeviceGroupRequestSchema,
	AddDeviceToGroupRequestSchema,
	RemoveDeviceFromGroupRequestSchema,
	ValidateDynamicQueryRequestSchema,
	EvaluateDynamicGroupRequestSchema,
	SetDeviceGroupSyncIntervalRequestSchema,
	// Assignments
	CreateAssignmentRequestSchema,
	DeleteAssignmentRequestSchema,
	ListAssignmentsRequestSchema,
	GetDeviceAssignmentsRequestSchema,
	GetUserAssignmentsRequestSchema,
	// User Selections
	ListAvailableActionsRequestSchema,
	SetUserSelectionRequestSchema,
	// Dispatch & Execution
	DispatchActionRequestSchema,
	DispatchToMultipleRequestSchema,
	DispatchAssignedActionsRequestSchema,
	DispatchActionSetRequestSchema,
	DispatchDefinitionRequestSchema,
	DispatchToGroupRequestSchema,
	DispatchInstantActionRequestSchema,
	GetExecutionRequestSchema,
	ListExecutionsRequestSchema,
	// Audit Log
	ListAuditEventsRequestSchema,
	// LPS
	GetDeviceLpsPasswordsRequestSchema,
	// LUKS
	GetDeviceLuksKeysRequestSchema,
	CreateLuksTokenRequestSchema,
	RevokeLuksDeviceKeyRequestSchema,
	// OSQuery & Inventory
	DispatchOSQueryRequestSchema,
	GetOSQueryResultRequestSchema,
	GetDeviceInventoryRequestSchema,
	RefreshDeviceInventoryRequestSchema,
	// Roles & Permissions
	CreateRoleRequestSchema,
	GetRoleRequestSchema,
	ListRolesRequestSchema,
	UpdateRoleRequestSchema,
	DeleteRoleRequestSchema,
	AssignRoleToUserRequestSchema,
	RevokeRoleFromUserRequestSchema,
	ListPermissionsRequestSchema,
	// TOTP
	SetupTOTPRequestSchema,
	VerifyTOTPRequestSchema,
	DisableTOTPRequestSchema,
	AdminDisableUserTOTPRequestSchema,
	GetTOTPStatusRequestSchema,
	RegenerateBackupCodesRequestSchema,
	VerifyLoginTOTPRequestSchema,
	// User Groups
	CreateUserGroupRequestSchema,
	GetUserGroupRequestSchema,
	ListUserGroupsRequestSchema,
	UpdateUserGroupRequestSchema,
	DeleteUserGroupRequestSchema,
	AddUserToGroupRequestSchema,
	RemoveUserFromGroupRequestSchema,
	AssignRoleToUserGroupRequestSchema,
	RevokeRoleFromUserGroupRequestSchema,
	ListUserGroupsForUserRequestSchema,
	UpdateUserGroupQueryRequestSchema,
	ValidateUserGroupQueryRequestSchema,
	EvaluateDynamicUserGroupRequestSchema,
	// Identity Providers & SSO
	ListAuthMethodsRequestSchema,
	GetSSOLoginURLRequestSchema,
	SSOCallbackRequestSchema,
	CreateIdentityProviderRequestSchema,
	GetIdentityProviderRequestSchema,
	ListIdentityProvidersRequestSchema,
	UpdateIdentityProviderRequestSchema,
	DeleteIdentityProviderRequestSchema,
	ListIdentityLinksRequestSchema,
	UnlinkIdentityRequestSchema,
	EnableSCIMRequestSchema,
	DisableSCIMRequestSchema,
	RotateSCIMTokenRequestSchema,
	type IdentityProvider,
	type IdentityLink,
	type InventoryTableResult,
	type User,
	type Device,
	type RegistrationToken,
	type ManagedAction,
	type ActionSet,
	type Definition,
	type DeviceGroup,
	type Assignment,
	type ActionExecution,
	type AuditEvent,
	type CreateActionRequest,
	type UpdateActionParamsRequest,
	type Role,
	type PermissionInfo,
	type UserGroup,
	type UserGroupMember,
	type LpsPassword,
	type LuksKey,
	type AvailableItem
} from '../gen/ts/pm/v1/control_pb';
import type { ActionType } from '../gen/ts/pm/v1/actions_pb';
import { type ExecutionStatus, ErrorDetailSchema } from '../gen/ts/pm/v1/common_pb';
import { timestampDate } from '@bufbuild/protobuf/wkt';

export interface ClientOptions {
	getServerUrl: () => string;
	getAccessToken: () => string | null;
	getRefreshToken: () => string | null;
	ensureValidToken: () => Promise<void>;
	refreshToken: () => Promise<boolean>;
	onUnauthenticated: () => void;
	onAuthResponse: (accessToken: string, refreshToken: string, expiresAt: Date, user: User) => void;
	onUserUpdated: (user: User) => void;
}

export class ApiClient {
	private opts: ClientOptions;

	constructor(opts: ClientOptions) {
		this.opts = opts;
	}

	private getTransport() {
		const serverUrl = this.opts.getServerUrl();
		if (!serverUrl) {
			throw new Error('Server URL not configured');
		}

		return createConnectTransport({
			baseUrl: serverUrl,
			interceptors: [
				(next) => async (req) => {
					await this.opts.ensureValidToken();

					const token = this.opts.getAccessToken();
					if (token) {
						req.header.set('Authorization', `Bearer ${token}`);
					}

					try {
						return await next(req);
					} catch (error: unknown) {
						if (error instanceof ConnectError && error.code === Code.Unauthenticated) {
							const refreshed = await this.opts.refreshToken();
							if (refreshed) {
								const newToken = this.opts.getAccessToken();
								if (newToken) {
									req.header.set('Authorization', `Bearer ${newToken}`);
								}
								return await next(req);
							}
							this.opts.onUnauthenticated();
						}
						throw error;
					}
				}
			]
		});
	}

	private getClient() {
		return createClient(ControlService, this.getTransport());
	}

	private getAuthTransport() {
		const serverUrl = this.opts.getServerUrl();
		if (!serverUrl) {
			throw new Error('Server URL not configured');
		}

		return createConnectTransport({
			baseUrl: serverUrl
		});
	}

	private getAuthClient() {
		return createClient(ControlService, this.getAuthTransport());
	}

	// ============================================================================
	// Authentication
	// ============================================================================

	async login(email: string, password: string) {
		const client = this.getAuthClient();
		const response = await client.login(
			create(LoginRequestSchema, { email, password })
		);

		if (response.totpRequired) {
			return response;
		}

		if (response.accessToken && response.refreshToken && response.expiresAt && response.user) {
			this.opts.onAuthResponse(
				response.accessToken,
				response.refreshToken,
				timestampDate(response.expiresAt),
				response.user
			);
		}

		return response;
	}

	async verifyLoginTOTP(challenge: string, code: string) {
		const client = this.getAuthClient();
		const response = await client.verifyLoginTOTP(
			create(VerifyLoginTOTPRequestSchema, { challenge, code })
		);

		if (response.accessToken && response.refreshToken && response.expiresAt && response.user) {
			this.opts.onAuthResponse(
				response.accessToken,
				response.refreshToken,
				timestampDate(response.expiresAt),
				response.user
			);
		}

		return response;
	}

	async refreshTokenRPC() {
		const client = this.getAuthClient();
		return client.refreshToken(
			create(RefreshTokenRequestSchema, { refreshToken: this.opts.getRefreshToken() ?? '' })
		);
	}

	async logoutRPC() {
		const client = this.getAuthClient();
		return client.logout(
			create(LogoutRequestSchema, { refreshToken: this.opts.getRefreshToken() ?? '' })
		);
	}

	async getCurrentUser() {
		const client = this.getClient();
		const response = await client.getCurrentUser(
			create(GetCurrentUserRequestSchema, {})
		);
		if (response.user) {
			this.opts.onUserUpdated(response.user);
		}
		return response.user;
	}

	// ============================================================================
	// TOTP Two-Factor Authentication
	// ============================================================================

	async setupTOTP() {
		const client = this.getClient();
		return client.setupTOTP(create(SetupTOTPRequestSchema, {}));
	}

	async verifyTOTP(code: string) {
		const client = this.getClient();
		return client.verifyTOTP(create(VerifyTOTPRequestSchema, { code }));
	}

	async disableTOTP(password: string) {
		const client = this.getClient();
		return client.disableTOTP(create(DisableTOTPRequestSchema, { password }));
	}

	async adminDisableUserTOTP(userId: string) {
		const client = this.getClient();
		return client.adminDisableUserTOTP(
			create(AdminDisableUserTOTPRequestSchema, { userId })
		);
	}

	async getTOTPStatus() {
		const client = this.getClient();
		return client.getTOTPStatus(create(GetTOTPStatusRequestSchema, {}));
	}

	async regenerateBackupCodes(password: string) {
		const client = this.getClient();
		return client.regenerateBackupCodes(
			create(RegenerateBackupCodesRequestSchema, { password })
		);
	}

	// ============================================================================
	// Users
	// ============================================================================

	async createUser(email: string, password: string, roleIds: string[] = [], profile?: {
		displayName?: string;
		givenName?: string;
		familyName?: string;
		preferredUsername?: string;
	}) {
		const client = this.getClient();
		const response = await client.createUser(
			create(CreateUserRequestSchema, { email, password, roleIds, ...profile })
		);
		return response.user;
	}

	async getUser(id: string) {
		const client = this.getClient();
		const response = await client.getUser(create(GetUserRequestSchema, { id }));
		return response.user;
	}

	async listUsers(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listUsers(
			create(ListUsersRequestSchema, { pageSize, pageToken })
		);
	}

	async updateUserEmail(id: string, email: string) {
		const client = this.getClient();
		const response = await client.updateUserEmail(
			create(UpdateUserEmailRequestSchema, { id, email })
		);
		return response.user;
	}

	async updateUserPassword(id: string, currentPassword: string, newPassword: string) {
		const client = this.getClient();
		const response = await client.updateUserPassword(
			create(UpdateUserPasswordRequestSchema, { id, currentPassword, newPassword })
		);
		return response.user;
	}

	async setUserDisabled(id: string, disabled: boolean) {
		const client = this.getClient();
		const response = await client.setUserDisabled(
			create(SetUserDisabledRequestSchema, { id, disabled })
		);
		return response.user;
	}

	async updateUserProfile(id: string, profile: {
		displayName?: string;
		givenName?: string;
		familyName?: string;
		preferredUsername?: string;
		picture?: string;
		locale?: string;
	}) {
		const client = this.getClient();
		const response = await client.updateUserProfile(
			create(UpdateUserProfileRequestSchema, { id, ...profile })
		);
		return response.user;
	}

	async deleteUser(id: string) {
		const client = this.getClient();
		await client.deleteUser(create(DeleteUserRequestSchema, { id }));
	}

	// ============================================================================
	// Devices
	// ============================================================================

	async listDevices(
		pageSize: number = 50,
		pageToken: string = '',
		statusFilter: string = '',
		labelFilter: Record<string, string> = {}
	) {
		const client = this.getClient();
		return client.listDevices(
			create(ListDevicesRequestSchema, { pageSize, pageToken, statusFilter, labelFilter })
		);
	}

	async getDevice(id: string) {
		const client = this.getClient();
		const response = await client.getDevice(create(GetDeviceRequestSchema, { id }));
		return response.device;
	}

	async setDeviceLabel(id: string, key: string, value: string) {
		const client = this.getClient();
		const response = await client.setDeviceLabel(
			create(SetDeviceLabelRequestSchema, { id, key, value })
		);
		return response.device;
	}

	async removeDeviceLabel(id: string, key: string) {
		const client = this.getClient();
		const response = await client.removeDeviceLabel(
			create(RemoveDeviceLabelRequestSchema, { id, key })
		);
		return response.device;
	}

	async assignDevice(deviceId: string, userId: string) {
		const client = this.getClient();
		const response = await client.assignDevice(
			create(AssignDeviceRequestSchema, { deviceId, userId })
		);
		return response.device;
	}

	async unassignDevice(deviceId: string) {
		const client = this.getClient();
		const response = await client.unassignDevice(
			create(UnassignDeviceRequestSchema, { deviceId })
		);
		return response.device;
	}

	async deleteDevice(id: string) {
		const client = this.getClient();
		await client.deleteDevice(create(DeleteDeviceRequestSchema, { id }));
	}

	async setDeviceSyncInterval(id: string, syncIntervalMinutes: number) {
		const client = this.getClient();
		const response = await client.setDeviceSyncInterval(
			create(SetDeviceSyncIntervalRequestSchema, { id, syncIntervalMinutes })
		);
		return response.device;
	}

	// ============================================================================
	// Registration Tokens
	// ============================================================================

	async createToken(name: string, oneTime: boolean, maxUses: number = 0, expiresAt?: Date) {
		const client = this.getClient();
		const response = await client.createToken(
			create(CreateTokenRequestSchema, {
				name,
				oneTime,
				maxUses,
				expiresAt: expiresAt
					? { seconds: BigInt(Math.floor(expiresAt.getTime() / 1000)), nanos: 0 }
					: undefined
			})
		);
		return response.token;
	}

	async getToken(id: string) {
		const client = this.getClient();
		const response = await client.getToken(create(GetTokenRequestSchema, { id }));
		return response.token;
	}

	async listTokens(pageSize: number = 50, pageToken: string = '', includeDisabled: boolean = false) {
		const client = this.getClient();
		return client.listTokens(
			create(ListTokensRequestSchema, { pageSize, pageToken, includeDisabled })
		);
	}

	async renameToken(id: string, name: string) {
		const client = this.getClient();
		const response = await client.renameToken(
			create(RenameTokenRequestSchema, { id, name })
		);
		return response.token;
	}

	async setTokenDisabled(id: string, disabled: boolean) {
		const client = this.getClient();
		const response = await client.setTokenDisabled(
			create(SetTokenDisabledRequestSchema, { id, disabled })
		);
		return response.token;
	}

	async deleteToken(id: string) {
		const client = this.getClient();
		await client.deleteToken(create(DeleteTokenRequestSchema, { id }));
	}

	// ============================================================================
	// Actions (single executable actions)
	// ============================================================================

	async createAction(data: Omit<CreateActionRequest, '$typeName'>) {
		const client = this.getClient();
		const response = await client.createAction(
			create(CreateActionRequestSchema, data)
		);
		return response.action;
	}

	async getAction(id: string) {
		const client = this.getClient();
		const response = await client.getAction(create(GetActionRequestSchema, { id }));
		return response.action;
	}

	async listActions(pageSize: number = 50, pageToken: string = '', typeFilter?: ActionType) {
		const client = this.getClient();
		return client.listActions(
			create(ListActionsRequestSchema, { pageSize, pageToken, typeFilter: typeFilter ?? 0 })
		);
	}

	async renameAction(id: string, name: string) {
		const client = this.getClient();
		const response = await client.renameAction(
			create(RenameActionRequestSchema, { id, name })
		);
		return response.action;
	}

	async updateActionDescription(id: string, description: string) {
		const client = this.getClient();
		const response = await client.updateActionDescription(
			create(UpdateActionDescriptionRequestSchema, { id, description })
		);
		return response.action;
	}

	async updateActionParams(data: Omit<UpdateActionParamsRequest, '$typeName'>) {
		const client = this.getClient();
		const response = await client.updateActionParams(
			create(UpdateActionParamsRequestSchema, data)
		);
		return response.action;
	}

	async deleteAction(id: string) {
		const client = this.getClient();
		await client.deleteAction(create(DeleteActionRequestSchema, { id }));
	}

	// ============================================================================
	// Action Sets (collection of actions)
	// ============================================================================

	async createActionSet(name: string, description: string = '') {
		const client = this.getClient();
		const response = await client.createActionSet(
			create(CreateActionSetRequestSchema, { name, description })
		);
		return response.set;
	}

	async getActionSet(id: string) {
		const client = this.getClient();
		return client.getActionSet(create(GetActionSetRequestSchema, { id }));
	}

	async listActionSets(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listActionSets(
			create(ListActionSetsRequestSchema, { pageSize, pageToken })
		);
	}

	async renameActionSet(id: string, name: string) {
		const client = this.getClient();
		const response = await client.renameActionSet(
			create(RenameActionSetRequestSchema, { id, name })
		);
		return response.set;
	}

	async updateActionSetDescription(id: string, description: string) {
		const client = this.getClient();
		const response = await client.updateActionSetDescription(
			create(UpdateActionSetDescriptionRequestSchema, { id, description })
		);
		return response.set;
	}

	async deleteActionSet(id: string) {
		const client = this.getClient();
		await client.deleteActionSet(create(DeleteActionSetRequestSchema, { id }));
	}

	async addActionToSet(setId: string, actionId: string, sortOrder: number = 0) {
		const client = this.getClient();
		const response = await client.addActionToSet(
			create(AddActionToSetRequestSchema, { setId, actionId, sortOrder })
		);
		return response.set;
	}

	async removeActionFromSet(setId: string, actionId: string) {
		const client = this.getClient();
		const response = await client.removeActionFromSet(
			create(RemoveActionFromSetRequestSchema, { setId, actionId })
		);
		return response.set;
	}

	async reorderActionInSet(setId: string, actionId: string, newOrder: number) {
		const client = this.getClient();
		const response = await client.reorderActionInSet(
			create(ReorderActionInSetRequestSchema, { setId, actionId, newOrder })
		);
		return response.set;
	}

	// ============================================================================
	// Definitions (collection of action sets)
	// ============================================================================

	async createDefinition(name: string, description: string = '') {
		const client = this.getClient();
		const response = await client.createDefinition(
			create(CreateDefinitionRequestSchema, { name, description })
		);
		return response.definition;
	}

	async getDefinition(id: string) {
		const client = this.getClient();
		return client.getDefinition(create(GetDefinitionRequestSchema, { id }));
	}

	async listDefinitions(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listDefinitions(
			create(ListDefinitionsRequestSchema, { pageSize, pageToken })
		);
	}

	async renameDefinition(id: string, name: string) {
		const client = this.getClient();
		const response = await client.renameDefinition(
			create(RenameDefinitionRequestSchema, { id, name })
		);
		return response.definition;
	}

	async updateDefinitionDescription(id: string, description: string) {
		const client = this.getClient();
		const response = await client.updateDefinitionDescription(
			create(UpdateDefinitionDescriptionRequestSchema, { id, description })
		);
		return response.definition;
	}

	async deleteDefinition(id: string) {
		const client = this.getClient();
		await client.deleteDefinition(create(DeleteDefinitionRequestSchema, { id }));
	}

	async addActionSetToDefinition(definitionId: string, actionSetId: string, sortOrder: number = 0) {
		const client = this.getClient();
		const response = await client.addActionSetToDefinition(
			create(AddActionSetToDefinitionRequestSchema, { definitionId, actionSetId, sortOrder })
		);
		return response.definition;
	}

	async removeActionSetFromDefinition(definitionId: string, actionSetId: string) {
		const client = this.getClient();
		const response = await client.removeActionSetFromDefinition(
			create(RemoveActionSetFromDefinitionRequestSchema, { definitionId, actionSetId })
		);
		return response.definition;
	}

	async reorderActionSetInDefinition(definitionId: string, actionSetId: string, newOrder: number) {
		const client = this.getClient();
		const response = await client.reorderActionSetInDefinition(
			create(ReorderActionSetInDefinitionRequestSchema, { definitionId, actionSetId, newOrder })
		);
		return response.definition;
	}

	// ============================================================================
	// Device Groups
	// ============================================================================

	async createDeviceGroup(name: string, description: string = '', isDynamic: boolean = false, dynamicQuery: string = '') {
		const client = this.getClient();
		const response = await client.createDeviceGroup(
			create(CreateDeviceGroupRequestSchema, { name, description, isDynamic, dynamicQuery })
		);
		return response.group;
	}

	async getDeviceGroup(id: string) {
		const client = this.getClient();
		return client.getDeviceGroup(create(GetDeviceGroupRequestSchema, { id }));
	}

	async listDeviceGroups(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listDeviceGroups(
			create(ListDeviceGroupsRequestSchema, { pageSize, pageToken })
		);
	}

	async renameDeviceGroup(id: string, name: string) {
		const client = this.getClient();
		const response = await client.renameDeviceGroup(
			create(RenameDeviceGroupRequestSchema, { id, name })
		);
		return response.group;
	}

	async updateDeviceGroupDescription(id: string, description: string) {
		const client = this.getClient();
		const response = await client.updateDeviceGroupDescription(
			create(UpdateDeviceGroupDescriptionRequestSchema, { id, description })
		);
		return response.group;
	}

	async deleteDeviceGroup(id: string) {
		const client = this.getClient();
		await client.deleteDeviceGroup(create(DeleteDeviceGroupRequestSchema, { id }));
	}

	async addDeviceToGroup(groupId: string, deviceId: string) {
		const client = this.getClient();
		const response = await client.addDeviceToGroup(
			create(AddDeviceToGroupRequestSchema, { groupId, deviceId })
		);
		return response.group;
	}

	async removeDeviceFromGroup(groupId: string, deviceId: string) {
		const client = this.getClient();
		const response = await client.removeDeviceFromGroup(
			create(RemoveDeviceFromGroupRequestSchema, { groupId, deviceId })
		);
		return response.group;
	}

	async updateDeviceGroupQuery(id: string, isDynamic: boolean, dynamicQuery: string = '') {
		const client = this.getClient();
		const response = await client.updateDeviceGroupQuery(
			create(UpdateDeviceGroupQueryRequestSchema, { id, isDynamic, dynamicQuery })
		);
		return response.group;
	}

	async validateDynamicQuery(query: string) {
		const client = this.getClient();
		return client.validateDynamicQuery(
			create(ValidateDynamicQueryRequestSchema, { query })
		);
	}

	async evaluateDynamicGroup(id: string) {
		const client = this.getClient();
		return client.evaluateDynamicGroup(
			create(EvaluateDynamicGroupRequestSchema, { id })
		);
	}

	async setDeviceGroupSyncInterval(id: string, syncIntervalMinutes: number) {
		const client = this.getClient();
		const response = await client.setDeviceGroupSyncInterval(
			create(SetDeviceGroupSyncIntervalRequestSchema, { id, syncIntervalMinutes })
		);
		return response.group;
	}

	// ============================================================================
	// Assignments
	// ============================================================================

	async createAssignment(
		sourceType: 'action' | 'action_set' | 'definition',
		sourceId: string,
		targetType: 'device' | 'device_group' | 'user' | 'user_group',
		targetId: string,
		mode: number = 0
	) {
		const client = this.getClient();
		const response = await client.createAssignment(
			create(CreateAssignmentRequestSchema, { sourceType, sourceId, targetType, targetId, mode })
		);
		return response.assignment;
	}

	async batchCreateAssignments(
		sourceType: 'action' | 'action_set' | 'definition',
		sourceId: string,
		targets: Array<{ targetType: 'device' | 'device_group' | 'user' | 'user_group'; targetId: string }>,
		mode: number = 0
	) {
		return Promise.all(
			targets.map((t) =>
				this.createAssignment(sourceType, sourceId, t.targetType, t.targetId, mode)
			)
		);
	}

	async deleteAssignment(id: string) {
		const client = this.getClient();
		await client.deleteAssignment(create(DeleteAssignmentRequestSchema, { id }));
	}

	async listAssignments(
		pageSize: number = 50,
		pageToken: string = '',
		sourceType: string = '',
		sourceId: string = '',
		targetType: string = '',
		targetId: string = ''
	) {
		const client = this.getClient();
		return client.listAssignments(
			create(ListAssignmentsRequestSchema, { pageSize, pageToken, sourceType, sourceId, targetType, targetId })
		);
	}

	async getDeviceAssignments(deviceId: string) {
		const client = this.getClient();
		return client.getDeviceAssignments(
			create(GetDeviceAssignmentsRequestSchema, { deviceId })
		);
	}

	async getUserAssignments(userId: string) {
		const client = this.getClient();
		return client.getUserAssignments(
			create(GetUserAssignmentsRequestSchema, { userId })
		);
	}

	// ============================================================================
	// User Selections (available assignments)
	// ============================================================================

	async listAvailableActions(deviceId: string) {
		const client = this.getClient();
		const response = await client.listAvailableActions(
			create(ListAvailableActionsRequestSchema, { deviceId })
		);
		return response.items;
	}

	async setUserSelection(deviceId: string, sourceType: string, sourceId: string, selected: boolean) {
		const client = this.getClient();
		return client.setUserSelection(
			create(SetUserSelectionRequestSchema, { deviceId, sourceType, sourceId, selected })
		);
	}

	// ============================================================================
	// Action Dispatch & Execution
	// ============================================================================

	async dispatchAction(deviceId: string, actionId: string) {
		const client = this.getClient();
		const response = await client.dispatchAction(
			create(DispatchActionRequestSchema, {
				deviceId,
				actionSource: { case: 'actionId', value: actionId }
			})
		);
		return response.execution;
	}

	async dispatchToMultiple(deviceIds: string[], actionId: string) {
		const client = this.getClient();
		const response = await client.dispatchToMultiple(
			create(DispatchToMultipleRequestSchema, {
				deviceIds,
				actionSource: { case: 'actionId', value: actionId }
			})
		);
		return response.executions;
	}

	async dispatchAssignedActions(deviceId: string) {
		const client = this.getClient();
		const response = await client.dispatchAssignedActions(
			create(DispatchAssignedActionsRequestSchema, { deviceId })
		);
		return response.executions;
	}

	async dispatchActionSet(deviceId: string, actionSetId: string) {
		const client = this.getClient();
		const response = await client.dispatchActionSet(
			create(DispatchActionSetRequestSchema, { deviceId, actionSetId })
		);
		return response.executions;
	}

	async dispatchDefinition(deviceId: string, definitionId: string) {
		const client = this.getClient();
		const response = await client.dispatchDefinition(
			create(DispatchDefinitionRequestSchema, { deviceId, definitionId })
		);
		return response.executions;
	}

	async dispatchToGroup(
		groupId: string,
		actionSource: { case: 'actionId'; value: string } | { case: 'actionSetId'; value: string } | { case: 'definitionId'; value: string }
	) {
		const client = this.getClient();
		const response = await client.dispatchToGroup(
			create(DispatchToGroupRequestSchema, { groupId, actionSource })
		);
		return response.executions;
	}

	async dispatchInstantAction(deviceId: string, instantAction: ActionType) {
		const client = this.getClient();
		const response = await client.dispatchInstantAction(
			create(DispatchInstantActionRequestSchema, { deviceId, instantAction })
		);
		return response.execution;
	}

	async getExecution(id: string) {
		const client = this.getClient();
		const response = await client.getExecution(create(GetExecutionRequestSchema, { id }));
		return response.execution;
	}

	async listExecutions(
		pageSize: number = 50,
		pageToken: string = '',
		deviceId: string = '',
		statusFilter?: ExecutionStatus
	) {
		const client = this.getClient();
		return client.listExecutions(
			create(ListExecutionsRequestSchema, {
				pageSize, pageToken, deviceId, statusFilter: statusFilter ?? 0
			})
		);
	}

	async getDeviceLpsPasswords(deviceId: string) {
		const client = this.getClient();
		return client.getDeviceLpsPasswords(
			create(GetDeviceLpsPasswordsRequestSchema, { deviceId })
		);
	}

	async getDeviceLuksKeys(deviceId: string) {
		const client = this.getClient();
		return client.getDeviceLuksKeys(
			create(GetDeviceLuksKeysRequestSchema, { deviceId })
		);
	}

	async createLuksToken(deviceId: string, actionId: string) {
		const client = this.getClient();
		return client.createLuksToken(
			create(CreateLuksTokenRequestSchema, { deviceId, actionId })
		);
	}

	async revokeLuksDeviceKey(deviceId: string, actionId: string) {
		const client = this.getClient();
		return client.revokeLuksDeviceKey(
			create(RevokeLuksDeviceKeyRequestSchema, { deviceId, actionId })
		);
	}

	// ============================================================================
	// OSQuery & Device Inventory
	// ============================================================================

	async getDeviceInventory(deviceId: string, tableNames?: string[]) {
		const client = this.getClient();
		return client.getDeviceInventory(
			create(GetDeviceInventoryRequestSchema, { deviceId, tableNames: tableNames ?? [] })
		);
	}

	async refreshDeviceInventory(deviceId: string) {
		const client = this.getClient();
		return client.refreshDeviceInventory(
			create(RefreshDeviceInventoryRequestSchema, { deviceId })
		);
	}

	async dispatchOSQuery(deviceId: string, table: string, columns?: string[], limit?: number, rawSql?: string) {
		const client = this.getClient();
		const response = await client.dispatchOSQuery(
			create(DispatchOSQueryRequestSchema, {
				deviceId, table, columns: columns ?? [], limit: limit ?? 0, rawSql: rawSql ?? ''
			})
		);
		return response.queryId;
	}

	async getOSQueryResult(queryId: string) {
		const client = this.getClient();
		return client.getOSQueryResult(
			create(GetOSQueryResultRequestSchema, { queryId })
		);
	}

	async listAuditEvents(
		pageSize: number = 50,
		pageToken: string = '',
		actorId: string = '',
		streamType: string = '',
		eventType: string = ''
	) {
		const client = this.getClient();
		return client.listAuditEvents(
			create(ListAuditEventsRequestSchema, { pageSize, pageToken, actorId, streamType, eventType })
		);
	}

	// ============================================================================
	// Roles & Permissions
	// ============================================================================

	async createRole(name: string, description: string, permissions: string[]) {
		const client = this.getClient();
		const response = await client.createRole(
			create(CreateRoleRequestSchema, { name, description, permissions })
		);
		return response.role;
	}

	async getRole(id: string) {
		const client = this.getClient();
		return client.getRole(create(GetRoleRequestSchema, { id }));
	}

	async listRoles(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listRoles(
			create(ListRolesRequestSchema, { pageSize, pageToken })
		);
	}

	async updateRole(roleId: string, name: string, description: string, permissions: string[]) {
		const client = this.getClient();
		const response = await client.updateRole(
			create(UpdateRoleRequestSchema, { roleId, name, description, permissions })
		);
		return response.role;
	}

	async deleteRole(id: string) {
		const client = this.getClient();
		await client.deleteRole(create(DeleteRoleRequestSchema, { id }));
	}

	async assignRoleToUser(userId: string, roleId: string) {
		const client = this.getClient();
		await client.assignRoleToUser(
			create(AssignRoleToUserRequestSchema, { userId, roleId })
		);
	}

	async revokeRoleFromUser(userId: string, roleId: string) {
		const client = this.getClient();
		await client.revokeRoleFromUser(
			create(RevokeRoleFromUserRequestSchema, { userId, roleId })
		);
	}

	async listPermissions() {
		const client = this.getClient();
		return client.listPermissions(
			create(ListPermissionsRequestSchema, {})
		);
	}

	// ============================================================================
	// User Groups
	// ============================================================================

	async createUserGroup(name: string, description: string = '', isDynamic: boolean = false, dynamicQuery: string = '') {
		const client = this.getClient();
		const response = await client.createUserGroup(
			create(CreateUserGroupRequestSchema, { name, description, isDynamic, dynamicQuery })
		);
		return response.group;
	}

	async getUserGroup(id: string) {
		const client = this.getClient();
		return client.getUserGroup(create(GetUserGroupRequestSchema, { id }));
	}

	async listUserGroups(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listUserGroups(
			create(ListUserGroupsRequestSchema, { pageSize, pageToken })
		);
	}

	async updateUserGroup(id: string, name: string, description: string) {
		const client = this.getClient();
		const response = await client.updateUserGroup(
			create(UpdateUserGroupRequestSchema, { groupId: id, name, description })
		);
		return response.group;
	}

	async deleteUserGroup(id: string) {
		const client = this.getClient();
		await client.deleteUserGroup(create(DeleteUserGroupRequestSchema, { id }));
	}

	async addUserToGroup(groupId: string, userId: string) {
		const client = this.getClient();
		await client.addUserToGroup(
			create(AddUserToGroupRequestSchema, { groupId, userId })
		);
	}

	async removeUserFromGroup(groupId: string, userId: string) {
		const client = this.getClient();
		await client.removeUserFromGroup(
			create(RemoveUserFromGroupRequestSchema, { groupId, userId })
		);
	}

	async assignRoleToUserGroup(groupId: string, roleId: string) {
		const client = this.getClient();
		await client.assignRoleToUserGroup(
			create(AssignRoleToUserGroupRequestSchema, { groupId, roleId })
		);
	}

	async revokeRoleFromUserGroup(groupId: string, roleId: string) {
		const client = this.getClient();
		await client.revokeRoleFromUserGroup(
			create(RevokeRoleFromUserGroupRequestSchema, { groupId, roleId })
		);
	}

	async listUserGroupsForUser(userId: string) {
		const client = this.getClient();
		return client.listUserGroupsForUser(
			create(ListUserGroupsForUserRequestSchema, { userId })
		);
	}

	async updateUserGroupQuery(id: string, isDynamic: boolean, dynamicQuery: string) {
		const client = this.getClient();
		const response = await client.updateUserGroupQuery(
			create(UpdateUserGroupQueryRequestSchema, { id, isDynamic, dynamicQuery })
		);
		return response.group;
	}

	async validateUserGroupQuery(query: string) {
		const client = this.getClient();
		return client.validateUserGroupQuery(
			create(ValidateUserGroupQueryRequestSchema, { query })
		);
	}

	async evaluateDynamicUserGroup(id: string) {
		const client = this.getClient();
		return client.evaluateDynamicUserGroup(
			create(EvaluateDynamicUserGroupRequestSchema, { id })
		);
	}

	// ============================================================================
	// Identity Providers & SSO
	// ============================================================================

	async listAuthMethods(email: string = '') {
		const client = this.getAuthClient();
		return client.listAuthMethods(
			create(ListAuthMethodsRequestSchema, { email })
		);
	}

	async getSSOLoginURL(slug: string, redirectUrl: string) {
		const client = this.getAuthClient();
		return client.getSSOLoginURL(
			create(GetSSOLoginURLRequestSchema, { slug, redirectUrl })
		);
	}

	async ssoCallback(slug: string, code: string, state: string) {
		const client = this.getAuthClient();
		const response = await client.sSOCallback(
			create(SSOCallbackRequestSchema, { slug, code, state })
		);

		if (response.totpRequired) {
			return response;
		}

		if (response.accessToken && response.refreshToken && response.expiresAt && response.user) {
			this.opts.onAuthResponse(
				response.accessToken,
				response.refreshToken,
				timestampDate(response.expiresAt),
				response.user
			);
		}

		return response;
	}

	async createIdentityProvider(data: {
		name: string;
		slug: string;
		providerType: string;
		clientId: string;
		clientSecret: string;
		issuerUrl: string;
		authorizationUrl?: string;
		tokenUrl?: string;
		userinfoUrl?: string;
		scopes?: string[];
		autoCreateUsers?: boolean;
		autoLinkByEmail?: boolean;
		defaultRoleId?: string;
		disablePasswordForLinked?: boolean;
		groupClaim?: string;
		groupMapping?: Record<string, string>;
	}) {
		const client = this.getClient();
		const response = await client.createIdentityProvider(
			create(CreateIdentityProviderRequestSchema, data)
		);
		return response.provider;
	}

	async getIdentityProvider(id: string) {
		const client = this.getClient();
		const response = await client.getIdentityProvider(
			create(GetIdentityProviderRequestSchema, { id })
		);
		return response.provider;
	}

	async listIdentityProviders(pageSize: number = 50, pageToken: string = '') {
		const client = this.getClient();
		return client.listIdentityProviders(
			create(ListIdentityProvidersRequestSchema, { pageSize, pageToken })
		);
	}

	async updateIdentityProvider(data: {
		id: string;
		name?: string;
		enabled?: boolean;
		clientId?: string;
		clientSecret?: string;
		issuerUrl?: string;
		authorizationUrl?: string;
		tokenUrl?: string;
		userinfoUrl?: string;
		scopes?: string[];
		autoCreateUsers?: boolean;
		autoLinkByEmail?: boolean;
		defaultRoleId?: string;
		disablePasswordForLinked?: boolean;
		groupClaim?: string;
		groupMapping?: Record<string, string>;
	}) {
		const client = this.getClient();
		const response = await client.updateIdentityProvider(
			create(UpdateIdentityProviderRequestSchema, data)
		);
		return response.provider;
	}

	async deleteIdentityProvider(id: string) {
		const client = this.getClient();
		await client.deleteIdentityProvider(
			create(DeleteIdentityProviderRequestSchema, { id })
		);
	}

	async listIdentityLinks() {
		const client = this.getClient();
		return client.listIdentityLinks(
			create(ListIdentityLinksRequestSchema, {})
		);
	}

	async unlinkIdentity(linkId: string) {
		const client = this.getClient();
		await client.unlinkIdentity(
			create(UnlinkIdentityRequestSchema, { linkId })
		);
	}

	async enableSCIM(id: string) {
		const client = this.getClient();
		return client.enableSCIM(create(EnableSCIMRequestSchema, { id }));
	}

	async disableSCIM(id: string) {
		const client = this.getClient();
		await client.disableSCIM(create(DisableSCIMRequestSchema, { id }));
	}

	async rotateSCIMToken(id: string) {
		const client = this.getClient();
		return client.rotateSCIMToken(create(RotateSCIMTokenRequestSchema, { id }));
	}
}

/**
 * Extract the error code from a ConnectError's ErrorDetail, if present.
 */
export function getErrorCode(error: unknown): string | undefined {
	if (error instanceof ConnectError) {
		const details = error.findDetails(ErrorDetailSchema);
		if (details.length > 0) {
			return details[0].code;
		}
	}
	return undefined;
}

// Re-export types for convenience
export type {
	User, Device, RegistrationToken, ManagedAction, ActionSet, Definition,
	DeviceGroup, Assignment, ActionExecution, AuditEvent, InventoryTableResult,
	Role, PermissionInfo, UserGroup, UserGroupMember, IdentityProvider, IdentityLink,
	LpsPassword, LuksKey, CreateActionRequest, UpdateActionParamsRequest,
	AvailableItem
};
