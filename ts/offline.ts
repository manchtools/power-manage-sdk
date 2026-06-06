// Offline sync store using IndexedDB.
// Plain TypeScript — no framework dependencies.

import { openDB, type IDBPDatabase } from 'idb';
import { logger, describeError } from './logger.js';

const log = logger.named('offline');

const DB_NAME = 'power-manage-offline';
const DB_VERSION = 1;

interface OfflineDB {
	drafts: {
		key: string;
		value: {
			id: string;
			type: string;
			data: unknown;
			updatedAt: Date;
		};
	};
}

let dbPromise: Promise<IDBPDatabase<OfflineDB>> | null = null;

function getDB(): Promise<IDBPDatabase<OfflineDB>> {
	if (typeof indexedDB === 'undefined') {
		return Promise.reject(new Error('IndexedDB not available'));
	}

	if (!dbPromise) {
		dbPromise = openDB<OfflineDB>(DB_NAME, DB_VERSION, {
			upgrade(db) {
				if (!db.objectStoreNames.contains('drafts')) {
					db.createObjectStore('drafts', { keyPath: 'id' });
				}
			}
		});
	}
	return dbPromise;
}

export type DraftType =
	| 'create-token'
	| 'create-definition'
	| 'create-user'
	| 'device-label'
	| 'dispatch-action';

/**
 * DraftPayloadMap is intentionally empty so frontend code can declare
 * narrowed per-type shapes via TypeScript module augmentation:
 *
 *   declare module '@manchtools/power-manage-sdk/ts/offline' {
 *     interface DraftPayloadMap {
 *       'create-user': { email: string; displayName: string };
 *     }
 *   }
 *
 * Declaration merging cannot *narrow* a property that is already
 * declared on an interface (e.g. `unknown` cannot be replaced with a
 * struct), so the defaults live on a separate `BuiltinDraftPayloadMap`
 * type that the lookup falls back to. After augmentation
 * `store.getDraft('create-user')` returns the augmented shape;
 * un-augmented keys still resolve to `unknown`. F031 in
 * TECH_DEBT_AUDIT.md.
 */
export interface DraftPayloadMap {}

type BuiltinDraftPayloadMap = {
	'create-token': unknown;
	'create-definition': unknown;
	'create-user': unknown;
	'device-label': unknown;
	'dispatch-action': unknown;
};

type DraftPayload<T extends DraftType> = T extends keyof DraftPayloadMap
	? DraftPayloadMap[T]
	: T extends keyof BuiltinDraftPayloadMap
		? BuiltinDraftPayloadMap[T]
		: unknown;

export class OfflineStore {
	private drafts: Map<string, unknown> = new Map();
	private loaded = false;
	private listeners = new Set<() => void>();

	constructor() {
		if (typeof window !== 'undefined') {
			this.loadDrafts();
		}
	}

	private notify() {
		for (const fn of this.listeners) fn();
	}

	onChange(listener: () => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	private async loadDrafts() {
		try {
			const db = await getDB();
			const allDrafts = await db.getAll('drafts');
			const map = new Map<string, unknown>();
			for (const draft of allDrafts) {
				map.set(draft.id, draft.data);
			}
			this.drafts = map;
			this.loaded = true;
			this.notify();
		} catch (error) {
			log.error('failed to load drafts', describeError(error));
			this.loaded = true;
			this.notify();
		}
	}

	get isLoaded() {
		return this.loaded;
	}

	getDraft<T extends DraftType>(type: T, id: string = 'default'): DraftPayload<T> | undefined {
		const key = `${type}:${id}`;
		return this.drafts.get(key) as DraftPayload<T> | undefined;
	}

	hasDraft(type: DraftType, id: string = 'default'): boolean {
		const key = `${type}:${id}`;
		return this.drafts.has(key);
	}

	async saveDraft<T extends DraftType>(
		type: T,
		data: DraftPayload<T>,
		id: string = 'default'
	): Promise<void> {
		const key = `${type}:${id}`;

		// Persist to IndexedDB FIRST. Only update the in-memory map after a
		// successful write — otherwise the UI would advertise "saved" while
		// the next page load loses the data. The error is rethrown so the
		// caller can surface it.
		try {
			const db = await getDB();
			await db.put('drafts', {
				id: key,
				type,
				data,
				updatedAt: new Date()
			});
		} catch (error) {
			log.error('failed to save draft', describeError(error));
			throw error;
		}

		const newMap = new Map(this.drafts);
		newMap.set(key, data);
		this.drafts = newMap;
		this.notify();
	}

	async clearDraft(type: DraftType, id: string = 'default'): Promise<void> {
		const key = `${type}:${id}`;

		// Same ordering rule as saveDraft — persist before mutating in-memory.
		try {
			const db = await getDB();
			await db.delete('drafts', key);
		} catch (error) {
			log.error('failed to clear draft', describeError(error));
			throw error;
		}

		const newMap = new Map(this.drafts);
		newMap.delete(key);
		this.drafts = newMap;
		this.notify();
	}

	async clearAllDrafts(): Promise<void> {
		try {
			const db = await getDB();
			await db.clear('drafts');
		} catch (error) {
			log.error('failed to clear all drafts', describeError(error));
			throw error;
		}

		this.drafts = new Map();
		this.notify();
	}

	getDraftsOfType<T extends DraftType>(type: T): Map<string, DraftPayload<T>> {
		const result = new Map<string, DraftPayload<T>>();
		for (const [key, value] of this.drafts.entries()) {
			if (key.startsWith(`${type}:`)) {
				const id = key.slice(type.length + 1);
				result.set(id, value as DraftPayload<T>);
			}
		}
		return result;
	}
}
