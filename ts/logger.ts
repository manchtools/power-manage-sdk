// Structured logger for the TypeScript SDK.
//
// Why this file exists: ts/auth.ts, ts/config.ts and ts/offline.ts
// historically used a mix of silent `catch {}` and raw `console.error`
// calls. Audit finding #5: silent catches hide real failures and raw
// `console.error` strings are unstructured — they can't be filtered
// at a sink, can't carry per-error metadata, and can't be diverted in
// tests.
//
// The logger here is intentionally small. It does NOT:
//   - depend on a third-party logger library (lean wire size);
//   - export persistent sinks (the SDK is consumed by both browser and
//     Node code; persistence is a higher-layer concern);
//   - duplicate fields on every call (the optional `context` arg covers
//     the per-call data and the global logger config covers the
//     ambient fields like the SDK version).
//
// Usage:
//
//   import { logger } from './logger.js';
//   logger.warn('failed to parse stored auth blob; falling back to empty', { error });
//
// Or with a named sub-logger:
//
//   const log = logger.named('auth');
//   log.debug('token refresh fired', { tokenAgeMs });
//
// Tests:
//
//   import { setLogSink, resetLogSink } from './logger.js';
//   const events: LogEvent[] = [];
//   setLogSink(e => events.push(e));
//   // … run code …
//   resetLogSink();

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
	debug: 10,
	info: 20,
	warn: 30,
	error: 40,
};

/** A single emitted log entry. */
export interface LogEvent {
	/** Severity. Filtered against the logger's minimum level. */
	level: LogLevel;
	/** Logical name of the sub-logger (e.g. "auth", "config"). */
	name: string;
	/** Human-readable message. */
	message: string;
	/** Optional structured payload — exception details, identifiers,
	 * timing, anything the caller wants to surface. */
	context?: Record<string, unknown>;
	/** Wall-clock time the event was created. ISO 8601, UTC. */
	timestamp: string;
}

/** A function that consumes log events. Defaults to consoleSink. */
export type LogSink = (event: LogEvent) => void;

/** The default sink writes to console at the matching severity. We
 * keep this distinct from the test sink so production telemetry
 * doesn't accidentally swallow itself in the absence of an explicit
 * sink replacement. */
function consoleSink(e: LogEvent): void {
	const prefix = `[${e.timestamp}] ${e.level.toUpperCase()} ${e.name}:`;
	switch (e.level) {
		case 'debug':
		case 'info':
			// eslint-disable-next-line no-console
			console.log(prefix, e.message, e.context ?? '');
			return;
		case 'warn':
			// eslint-disable-next-line no-console
			console.warn(prefix, e.message, e.context ?? '');
			return;
		case 'error':
			// eslint-disable-next-line no-console
			console.error(prefix, e.message, e.context ?? '');
			return;
	}
}

let currentSink: LogSink = consoleSink;
let currentMinLevel: LogLevel = 'info';

/** Replace the global sink. Returns the previous sink. */
export function setLogSink(sink: LogSink): LogSink {
	const previous = currentSink;
	currentSink = sink;
	return previous;
}

/** Restore the default console sink and the default minimum level
 * (info). Symmetric with setLogSink for tests. */
export function resetLogSink(): void {
	currentSink = consoleSink;
	currentMinLevel = 'info';
}

/** Set the minimum severity that will be forwarded to the sink.
 * Events below this level are dropped silently. Default: 'info'. */
export function setLogLevel(level: LogLevel): void {
	currentMinLevel = level;
}

function emit(name: string, level: LogLevel, message: string, context?: Record<string, unknown>): void {
	if (LEVEL_ORDER[level] < LEVEL_ORDER[currentMinLevel]) return;
	currentSink({
		level,
		name,
		message,
		context,
		timestamp: new Date().toISOString(),
	});
}

/** A sub-logger anchored at a given name. Returned by `logger.named`
 * so the SDK's individual modules can carry their own log prefix
 * without each call site having to repeat it. */
export interface Logger {
	name: string;
	debug(message: string, context?: Record<string, unknown>): void;
	info(message: string, context?: Record<string, unknown>): void;
	warn(message: string, context?: Record<string, unknown>): void;
	error(message: string, context?: Record<string, unknown>): void;
	/** Create a child sub-logger that prepends a dotted segment. */
	named(child: string): Logger;
}

function makeLogger(name: string): Logger {
	return {
		name,
		debug: (m, c) => emit(name, 'debug', m, c),
		info: (m, c) => emit(name, 'info', m, c),
		warn: (m, c) => emit(name, 'warn', m, c),
		error: (m, c) => emit(name, 'error', m, c),
		named: (child) => makeLogger(`${name}.${child}`),
	};
}

/** The root logger for the SDK. Sub-loggers via `logger.named(...)`. */
export const logger: Logger = makeLogger('pm-sdk');

/** Best-effort serialization of an `unknown` (typically a `catch`
 * error binding) into a JSON-safe shape for the `context` payload.
 * Avoids stringifying objects the structured sink can keep alive. */
export function describeError(err: unknown): Record<string, unknown> {
	if (err instanceof Error) {
		return { name: err.name, message: err.message, stack: err.stack };
	}
	if (typeof err === 'object' && err !== null) {
		return { value: err as Record<string, unknown> };
	}
	return { value: String(err) };
}
