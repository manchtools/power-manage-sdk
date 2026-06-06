import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
	logger,
	setLogSink,
	resetLogSink,
	setLogLevel,
	describeError,
	type LogEvent,
} from '../../ts/logger.js';

describe('logger', () => {
	let events: LogEvent[];

	beforeEach(() => {
		events = [];
		setLogSink((e) => events.push(e));
		setLogLevel('debug');
	});

	afterEach(() => {
		resetLogSink();
	});

	it('forwards events to the configured sink with the right level + name', () => {
		const auth = logger.named('auth');
		auth.warn('something off', { tokenAgeMs: 1234 });
		expect(events).toHaveLength(1);
		const ev = events[0]!;
		expect(ev.level).toBe('warn');
		expect(ev.name).toBe('pm-sdk.auth');
		expect(ev.message).toBe('something off');
		expect(ev.context).toEqual({ tokenAgeMs: 1234 });
	});

	it('emits an ISO-8601 timestamp', () => {
		logger.info('tick');
		expect(events[0]!.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
	});

	it('drops events below the configured minimum level', () => {
		setLogLevel('warn');
		logger.debug('quiet');
		logger.info('still quiet');
		logger.warn('audible');
		logger.error('loud');
		expect(events.map((e) => e.level)).toEqual(['warn', 'error']);
	});

	it('named() composes dotted prefixes for nested sub-loggers', () => {
		const child = logger.named('auth').named('refresh');
		child.info('rotated', { newExpiry: '2026-01-01T00:00:00.000Z' });
		expect(events[0]!.name).toBe('pm-sdk.auth.refresh');
	});
});

describe('describeError', () => {
	it('captures name + message + stack for Error instances', () => {
		const err = new Error('boom');
		const got = describeError(err);
		expect(got.name).toBe('Error');
		expect(got.message).toBe('boom');
		expect(typeof got.stack).toBe('string');
	});

	it('boxes non-Error values via the `value` field', () => {
		expect(describeError('plain string')).toEqual({ value: 'plain string' });
		expect(describeError(42)).toEqual({ value: '42' });
		expect(describeError(null)).toEqual({ value: 'null' });
	});

	it('passes objects through under the value field (keeps the object alive for sinks instead of stringifying)', () => {
		const arbitrary = { code: 'EBADF', detail: { fd: 5 } };
		expect(describeError(arbitrary)).toEqual({ value: arbitrary });
	});
});
