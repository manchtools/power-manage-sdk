---
title: Agent client
label: Client
description: The direct long-lived mTLS stream, bounded dispatch, and maintenance windows.
---

# Agent client

The client maintains one outbound bidirectional mTLS stream directly between
agent and control. Handshake, synchronization, heartbeats, delivery, results,
inventory, log/osquery replies, and terminal traffic share the stream.

## Transport

The agent validates control against the CA pinned at enrollment. Control
derives device identity from the client certificate and checks revocation
during the handshake.

Application frames are not separately signed. Both endpoints are trusted and
there is no relay or offline verifier. Classified secret fields use
recipient-bound X25519 envelopes as described in [Crypto](/concepts/crypto).

## Robustness

- bound inbound frame size;
- reject malformed and nil payloads before handlers;
- serialize sends with context-aware cancellation;
- bound worker queues and goroutine fan-out;
- isolate a handler panic without leaking secrets; and
- preserve on-wire ordering.

Control commits a delivery before sending it. The agent durably records its
`delivery_id` before acknowledging receipt. Retries reuse the same ID and
results are idempotent.

Before a non-idempotent side effect, the agent records `STARTED`. A crash
after that point reports `INDETERMINATE` instead of repeating the effect.

## Maintenance windows

The maintenance package is the shared parser and evaluator. The agent applies
windows using its local wall clock. Already received scheduled work can
continue while control is temporarily unavailable.

## Related

- [Crypto helpers](/concepts/crypto)
- [Errors](/concepts/errors)
