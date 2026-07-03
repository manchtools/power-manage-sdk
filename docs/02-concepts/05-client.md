---
title: Agent client & signed commands
label: Client & signing
description: The long-lived bidirectional stream between agent and gateway — dispatch robustness against a hostile relay, fail-closed action-signature verification, and maintenance-window evaluation.
---

# Agent client & signed commands

Three pieces of the SDK carry the agent's server-facing behaviour: the
`Client` (a long-lived bidirectional stream to the gateway), the `verify`
package (signatures over every server-originated command), and the
`maintenance` package (when scheduled work is allowed to run). The common
thread: the gateway is the *least-trusted* server-side actor, so the client
treats every inbound frame as potentially hostile and every command as
unauthenticated until a CA signature says otherwise.

## The stream

The agent connects over mTLS and keeps one bidirectional stream open;
heartbeats, action results, inventory, and terminal I/O all multiplex over
it.

<!-- docref: begin src=client.go#WithMTLSFromPEM:7e7dc2c3,client.go#WithMTLSFromPEMAndSystemRoots:0388329a -->
Gateway trust is strict: the mTLS options verify the server **only** against
the enrolled internal CA — system roots are deliberately not consulted, so a
certificate signed by any public CA cannot impersonate the gateway even with
a matching SNI. The `...AndSystemRoots` variant exists solely for
control-server endpoints fronted by a public CA (a reverse proxy with Let's
Encrypt); using it for the gateway connection would broaden the gateway's
trust and is explicitly warned against.
<!-- docref: end -->

<!-- docref: begin src=client.go#MinHeartbeatInterval:2278f3a7,client.go#Client.applyWelcomeHeartbeat:64ed1259 -->
The server can retune the heartbeat cadence via its Welcome message, but the
SDK clamps the value into a safe band (5 seconds to 5 minutes) before
applying it — a misconfigured or malicious server can never push the cadence
into stream spam or make the agent look dead to liveness tracking. A
zero/unset interval keeps the caller-supplied one.
<!-- docref: end -->

<!-- docref: begin src=client.go#Client.send:881c9f04 -->
All writes to the stream are serialized through a context-aware send lock:
concurrent writers (heartbeat, results, terminal output) can never interleave
bytes on the wire, and a sender stalled behind a peer that stops draining
abandons its claim on its own deadline instead of wedging every other sender
behind it. At most one send is ever in flight, so the on-wire serialization
guarantee survives even an abandoned send.
<!-- docref: end -->

## Dispatch robustness

Inbound frames get no benefit of the doubt — a compromised gateway is in the
threat model.

<!-- docref: begin src=client.go#maxInboundMessageBytes:794c84c6,client.go#Client.validateInbound:e0ff57f2,client.go#Client.dispatchServerMessage:afa7bd96 -->
A single inbound message is size-capped (16 MiB — far above any legitimate
control frame), so a multi-gigabyte frame cannot force an allocation; the
connection that receives one is torn down with a resource-exhausted error.
Every concrete command payload is then re-validated against the shared
`validate` tags at the SDK boundary — a malformed-but-non-nil frame
(out-of-range PTY dimensions, a non-ULID session id, an empty envelope) is
dropped before it reaches a handler. Nil oneof payloads are dropped
non-fatally, unknown payload variants from a newer server are logged and
dropped rather than tearing the connection down, and a **panic inside any
handler is recovered and turned into a dropped frame** — one hostile or buggy
invocation cannot crash-loop the agent.
<!-- docref: end -->

<!-- docref: begin src=client.go#actionQueueDepth:794c84c6,client.go#Client.runDispatchedAction:528ff624 -->
Server-dispatched actions execute on a single worker goroutine off the
receive loop — one at a time, in order — so a long-running action can never
head-of-line-block terminal input or a stop request. The queue is bounded; a
flood beyond it is dropped with a loud warning (the server re-dispatches
unacked actions on reconnect) rather than allowed to grow without bound or to
block the receive loop.
<!-- docref: end -->

## Every server command is signed

The stream being authenticated is not enough: the gateway relays commands, it
does not originate them. Authority comes from a control-server CA signature
on the command itself.

<!-- docref: begin src=client.go#StreamHandler:0163986d,verify/verify.go#ActionVerifier.Verify:c3b3df3c,verify/envelope.go#MarshalEnvelope:eeb40f10 -->
An action arrives as opaque **envelope bytes plus a signature**. The handler
contract is verify-then-execute-the-same-bytes: verify the signature over
exactly the bytes received, then unmarshal *those same bytes* to execute —
never a re-marshalled copy — so the executed action is byte-for-byte the
verified action. The envelope covers the whole command (id, type, params,
desired state, timeout, schedule, target device), which means a compromised
relay cannot flip a field, swap params, or retarget the device under a
still-valid signature.
<!-- docref: end -->

<!-- docref: begin src=verify/verify.go#ActionSignatureDomain:fe438abc,verify/verify.go#canonicalDigest:8e724a35 -->
Every signing surface that shares the CA key — actions, osquery dispatches,
log queries, LUKS revocations, inventory requests, the LPS public key — has
its own domain string, and the digest mixes in the domain with a length
prefix, so a signature minted for one surface can never be replayed against
another.
<!-- docref: end -->

<!-- docref: begin src=verify/verify.go#ActionVerifier.verifyDigest:5f7ba25f -->
Verification is fail-closed: an empty signature or payload is rejected, and
only ECDSA and RSA keys are accepted — any other key type (including
Ed25519) is an explicit error, so a key-type drift between server and agent
surfaces loudly instead of as a silent mismatch.
<!-- docref: end -->

## Maintenance windows

<!-- docref: begin src=maintenance/window.go#IsAllowed:8a918a14,maintenance/window.go#Union:be10448d,maintenance/window.go#Validate:eb666b47 -->
The `maintenance` package is the **shared** parser, validator, union resolver
and evaluator for maintenance windows, so server and agent agree bit-for-bit
on what counts as an allowed dispatch moment. An empty window means "always
allowed" (the feature is opt-in); entries within a window OR together, and
the union across a device's groups ORs again — if any reaching group has no
window, the union collapses to unconstrained. Evaluation runs against the
device's **local** wall-clock on the agent; the server never computes
allowedness, because the device is the only authority on its own clock.
<!-- docref: end -->

## Related

- [Crypto helpers](/concepts/crypto) — the AEAD, sealing, and certificate
  primitives underneath.
- [Errors](/concepts/errors) — how failures surface across the SDK.
