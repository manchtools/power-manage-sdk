---
title: Crypto helpers
label: Crypto
description: AEAD, recipient-bound field sealing, and device certificate helpers.
---

# Crypto helpers

The SDK provides mechanisms, not server policy. The sole system security
design is the workspace target document.

## At-rest encryption

AES-256-GCM helpers require non-empty, domain-separated AAD. Nonces come from
the operating-system CSPRNG. Wrong keys, wrong AAD, malformed ciphertext, and
authentication failure return no plaintext.

Server code binds each secret to its resource context and purpose. Transport
field sealing is not reused as storage encryption.

## Agent/control field sealing

Classified protobuf fields carry versioned opaque X25519 envelopes in both
directions. The sealing context binds:

- protocol version and direction;
- message and field;
- device identity; and
- the relevant action, delivery, or terminal session.

Agent-to-control LPS/LUKS values seal to control. Control-to-agent secret
values seal to that agent. Decryption occurs only at the narrow feature sink.
A wrong recipient, context, or modified ciphertext fails closed.

Field sealing reduces accidental plaintext exposure through generic protobuf
formatting and debugging. Metadata-only logging and explicit secret-sink
guards remain mandatory.

## Certificates

The device generates an Ed25519 identity key and CSR locally. The private key
never leaves the device. Enrollment may pin the CA fingerprint, and renewal
must preserve CA continuity or require clean re-enrollment.

Ordinary application frames are not separately signed. Direct mTLS authenticates
and protects the agent/control stream.

## Related

- [Client](/concepts/client)
- [Errors](/concepts/errors)
