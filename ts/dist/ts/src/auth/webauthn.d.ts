/**
 * Decode base64url string to Uint8Array.
 */
export declare function base64urlToBuffer(base64url: string): ArrayBuffer;
/**
 * Encode ArrayBuffer to base64url string.
 */
export declare function bufferToBase64url(buffer: ArrayBuffer): string;
/**
 * Parse WebAuthn creation options from server response.
 */
export declare function parseCreationOptions(optionsJson: string): CredentialCreationOptions;
/**
 * Parse WebAuthn request options from server response.
 */
export declare function parseRequestOptions(optionsJson: string): CredentialRequestOptions;
/**
 * Encode PublicKeyCredential (registration response) for server.
 */
export declare function encodeAttestationResponse(credential: PublicKeyCredential): string;
/**
 * Encode PublicKeyCredential (login response) for server.
 */
export declare function encodeAssertionResponse(credential: PublicKeyCredential): string;
/**
 * Check if WebAuthn is available in the browser.
 */
export declare function isWebAuthnAvailable(): boolean;
/**
 * Check if platform authenticator (e.g., Face ID, Touch ID, Windows Hello) is available.
 */
export declare function isPlatformAuthenticatorAvailable(): Promise<boolean>;
/**
 * Check if conditional UI (autofill) is available.
 */
export declare function isConditionalUIAvailable(): Promise<boolean>;
/**
 * Create a new passkey (registration).
 */
export declare function createPasskey(optionsJson: string): Promise<string>;
/**
 * Authenticate with a passkey (login).
 */
export declare function authenticateWithPasskey(optionsJson: string, useConditionalUI?: boolean): Promise<string>;
//# sourceMappingURL=webauthn.d.ts.map