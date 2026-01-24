// WebAuthn browser helpers for passkey authentication

/**
 * Decode base64url string to Uint8Array.
 */
export function base64urlToBuffer(base64url: string): ArrayBuffer {
  // Convert base64url to base64
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with '=' if needed
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  // Decode
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encode ArrayBuffer to base64url string.
 */
export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Encode to base64
  const base64 = btoa(binary);
  // Convert to base64url
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Parse WebAuthn creation options from server response.
 */
export function parseCreationOptions(optionsJson: string): CredentialCreationOptions {
  const options = JSON.parse(optionsJson);

  return {
    publicKey: {
      ...options.publicKey,
      challenge: base64urlToBuffer(options.publicKey.challenge),
      user: {
        ...options.publicKey.user,
        id: base64urlToBuffer(options.publicKey.user.id),
      },
      excludeCredentials: options.publicKey.excludeCredentials?.map(
        (cred: { id: string; type: string; transports?: string[] }) => ({
          ...cred,
          id: base64urlToBuffer(cred.id),
        })
      ),
    },
  };
}

/**
 * Parse WebAuthn request options from server response.
 */
export function parseRequestOptions(optionsJson: string): CredentialRequestOptions {
  const options = JSON.parse(optionsJson);

  return {
    publicKey: {
      ...options.publicKey,
      challenge: base64urlToBuffer(options.publicKey.challenge),
      allowCredentials: options.publicKey.allowCredentials?.map(
        (cred: { id: string; type: string; transports?: string[] }) => ({
          ...cred,
          id: base64urlToBuffer(cred.id),
        })
      ),
    },
  };
}

/**
 * Encode PublicKeyCredential (registration response) for server.
 */
export function encodeAttestationResponse(
  credential: PublicKeyCredential
): string {
  const response = credential.response as AuthenticatorAttestationResponse;

  const encoded = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
    },
  };

  return JSON.stringify(encoded);
}

/**
 * Encode PublicKeyCredential (login response) for server.
 */
export function encodeAssertionResponse(
  credential: PublicKeyCredential
): string {
  const response = credential.response as AuthenticatorAssertionResponse;

  const encoded = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
  };

  return JSON.stringify(encoded);
}

/**
 * Check if WebAuthn is available in the browser.
 */
export function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === 'function'
  );
}

/**
 * Check if platform authenticator (e.g., Face ID, Touch ID, Windows Hello) is available.
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnAvailable()) return false;

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Check if conditional UI (autofill) is available.
 */
export async function isConditionalUIAvailable(): Promise<boolean> {
  if (!isWebAuthnAvailable()) return false;

  try {
    const pk = PublicKeyCredential as unknown as {
      isConditionalMediationAvailable?: () => Promise<boolean>;
    };
    if (pk.isConditionalMediationAvailable) {
      return await pk.isConditionalMediationAvailable();
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Create a new passkey (registration).
 */
export async function createPasskey(
  optionsJson: string
): Promise<string> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  const options = parseCreationOptions(optionsJson);
  const credential = (await navigator.credentials.create(
    options
  )) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to create credential');
  }

  return encodeAttestationResponse(credential);
}

/**
 * Authenticate with a passkey (login).
 */
export async function authenticateWithPasskey(
  optionsJson: string,
  useConditionalUI = false
): Promise<string> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  const options = parseRequestOptions(optionsJson);

  if (useConditionalUI) {
    (options as { mediation?: string }).mediation = 'conditional';
  }

  const credential = (await navigator.credentials.get(
    options
  )) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to authenticate');
  }

  return encodeAssertionResponse(credential);
}
