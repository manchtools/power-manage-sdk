// Power Manage API Client

import { createConnectTransport } from '@connectrpc/connect-web';
import { createClient, type Client } from '@connectrpc/connect';

import { AuthService } from '../../gen/ts/powermanage/v1/auth_connect.js';
import { UserService } from '../../gen/ts/powermanage/v1/users_connect.js';
import { DeviceService } from '../../gen/ts/powermanage/v1/devices_connect.js';
import { DeviceGroupService } from '../../gen/ts/powermanage/v1/device_groups_connect.js';
import {
  ActionManagementService,
  ActionSetService,
  DefinitionService,
  AssignmentService,
} from '../../gen/ts/powermanage/v1/action_management_connect.js';

import { getConfigStore } from './config/index.js';
import { getAuthStore } from './auth/store.js';
import {
  createPasskey,
  authenticateWithPasskey,
} from './auth/webauthn.js';

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
export class PowerManageClient {
  private transport: ReturnType<typeof createConnectTransport>;

  // Service clients
  public readonly auth: Client<typeof AuthService>;
  public readonly users: Client<typeof UserService>;
  public readonly devices: Client<typeof DeviceService>;
  public readonly deviceGroups: Client<typeof DeviceGroupService>;
  public readonly actions: Client<typeof ActionManagementService>;
  public readonly actionSets: Client<typeof ActionSetService>;
  public readonly definitions: Client<typeof DefinitionService>;
  public readonly assignments: Client<typeof AssignmentService>;

  constructor(options: PowerManageClientOptions = {}) {
    // Use configured URL, or empty string for same-origin requests (via proxy)
    const serverUrl = options.serverUrl ?? getConfigStore().getServerUrl() ?? '';

    this.transport = createConnectTransport({
      baseUrl: serverUrl,
      credentials: options.credentials !== false ? 'include' : 'omit',
    });

    // Initialize service clients
    this.auth = createClient(AuthService, this.transport);
    this.users = createClient(UserService, this.transport);
    this.devices = createClient(DeviceService, this.transport);
    this.deviceGroups = createClient(DeviceGroupService, this.transport);
    this.actions = createClient(ActionManagementService, this.transport);
    this.actionSets = createClient(ActionSetService, this.transport);
    this.definitions = createClient(DefinitionService, this.transport);
    this.assignments = createClient(AssignmentService, this.transport);
  }

  /**
   * Begin WebAuthn registration with a registration code.
   */
  async beginRegistration(registrationCode: string) {
    const response = await this.auth.beginRegistration({ registrationCode });
    return response;
  }

  /**
   * Complete WebAuthn registration.
   */
  async finishRegistration(sessionId: string, optionsJson: string) {
    // Create passkey using browser WebAuthn API
    const attestationJson = await createPasskey(optionsJson);

    const response = await this.auth.finishRegistration({
      sessionId,
      attestationJson,
    });

    // Registration creates user but doesn't automatically log in
    // User needs to login after registration
    return response;
  }

  /**
   * Begin WebAuthn login.
   */
  async beginLogin(username?: string) {
    const response = await this.auth.beginLogin({
      username: username || '',
    });
    return response;
  }

  /**
   * Complete WebAuthn login.
   */
  async finishLogin(sessionId: string, optionsJson: string, useConditionalUI = false) {
    // Authenticate using browser WebAuthn API
    const assertionJson = await authenticateWithPasskey(optionsJson, useConditionalUI);

    const response = await this.auth.finishLogin({
      sessionId,
      assertionJson,
    });

    // Update auth store with session
    if (response.session && response.session.user) {
      getAuthStore().setSession(response.session.user, response.session.id);
    }

    return response;
  }

  /**
   * Logout and clear session.
   */
  async logout() {
    try {
      await this.auth.logout({});
    } finally {
      getAuthStore().clearSession();
    }
  }

  /**
   * Get current session from server.
   */
  async getSession() {
    const response = await this.auth.getSession({});
    return response;
  }

  /**
   * Check if server is reachable.
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.auth.getSession({});
      return true;
    } catch {
      return false;
    }
  }
}

// Singleton instance
let clientInstance: PowerManageClient | null = null;

/**
 * Get or create the global PowerManageClient instance.
 * Creates a new instance if server URL changes.
 */
export function getClient(options?: PowerManageClientOptions): PowerManageClient {
  const serverUrl = options?.serverUrl || getConfigStore().getServerUrl();

  // Create new instance if URL changed or doesn't exist
  if (!clientInstance) {
    clientInstance = new PowerManageClient(options);
  }

  return clientInstance;
}

/**
 * Reset the client instance (e.g., when server URL changes).
 */
export function resetClient(): void {
  clientInstance = null;
}
