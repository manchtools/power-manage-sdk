import { describe, expect, it } from 'vitest';
import { ApiClient } from './client';

// Regression for the wrapper that returned response.token and dropped the
// caFingerprintPin riding beside it by contract: agents require the pin at
// install time (-p), so every token created through this wrapper was
// un-enrollable without recomputing the pin out of band.
describe('createToken keeps the CA fingerprint pin beside the token', () => {
	it('returns the full response, token and pin together', async () => {
		const pin = 'ab'.repeat(32);
		const stubClient = {
			createToken: async () => ({
				token: { id: '01ARZ3NDEKTSV4RRFFQ69G5FAV', value: 'TOK-SECRET' },
				caFingerprintPin: pin
			})
		};
		// getClient is private to the class but is an ordinary property at
		// runtime; substituting `this` is the smallest seam that exercises the
		// real wrapper body without a network transport.
		const createToken = ApiClient.prototype.createToken as unknown as (
			this: { getClient: () => typeof stubClient },
			name: string,
			oneTime: boolean
		) => ReturnType<ApiClient['createToken']>;
		const result = await createToken.call({ getClient: () => stubClient }, 'first-device', true);
		expect(result.token?.value).toBe('TOK-SECRET');
		expect(result.caFingerprintPin).toBe(pin);
	});
});
