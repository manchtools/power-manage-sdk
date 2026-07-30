---
title: Crypto helpers
label: Crypto
description: The crypto package's guarantees — mandatory domain separation on every AEAD and seal, one-way X25519 sealing past a low-trust relay, and CSR / CA-continuity rules.
---

# Crypto helpers

The top-level `crypto` package holds the primitives the Power Manage trust
story is built from: authenticated encryption, asymmetric sealing, LPS
password sealing, and the certificate utilities used at agent enrollment and
renewal. The design rule across all of them: **misuse is rejected by
construction**, not left to caller discipline.

## No naked AEAD calls

<!-- docref: begin src=crypto/aead.go#SealWithAAD:462ff1c8,crypto/aead.go#ErrAADRequired:c7997fd7 -->
`SealWithAAD` encrypts with AES-256-GCM and **requires a non-empty AAD** —
an empty one is refused with `ErrAADRequired`. That makes domain separation
mandatory: two different ciphertext domains can never be confused or
cross-decrypted, and "forgot the AAD" is impossible to do silently. The
96-bit nonce is generated per call from `crypto/rand` and prepended to the
output; it is never taken from the caller, so nonce reuse under one key —
catastrophic for GCM — cannot be introduced by a caller mistake, and an RNG
failure fails closed rather than emitting a predictable nonce.
<!-- docref: end -->

<!-- docref: begin src=crypto/aead.go#OpenWithAAD:9ba6d7a3 -->
`OpenWithAAD` reverses it under the *same* key and AAD. Any authentication
failure — a wrong key, a wrong-domain AAD, a tampered ciphertext — returns an
error and **no plaintext**; a blob too short to carry its nonce and tag is
rejected up front with a precise `ErrMalformedCiphertext` rather than a
generic authentication failure.
<!-- docref: end -->

## Sealing to a public key

Some secrets must cross a relay that is not allowed to read them. The
sealing construction is ECIES-style: an ephemeral X25519 key agreement,
HKDF-SHA256, then the same AEAD.

<!-- docref: begin src=crypto/seal.go#SealToPublicKey:6b2352e6,crypto/seal.go#OpenWithPrivateKey:f52d2fda,crypto/seal.go#ErrInfoRequired:53c99fd6 -->
`SealToPublicKey` encrypts so that only the holder of the recipient's X25519
private key can open, and requires **both** a non-empty AAD and a non-empty
HKDF `info` string (`ErrInfoRequired`) — the info domain-separates every
sealing surface, so a blob sealed for one purpose can never open under
another even if the recipient key were reused. Both public keys are bound
into the HKDF salt, tying the derived key to this exact (ephemeral,
recipient) pair. `OpenWithPrivateKey` re-derives under the *same* info and
AAD; any mismatch — a tampered byte, a different context, the wrong key —
returns an error and no plaintext.
<!-- docref: end -->

## LPS and LUKS secret transport — removed by spec 41

~~The concrete consumers are Local Password Solution rotation and managed LUKS
passphrase storage (spec 25): the agent seals each rotated local password /
managed disk passphrase to the control server's key, so the relaying
gateway — the least-trusted server-side actor — can never read either.~~

**`SealLpsPassword` / `OpenLpsPassword` and `SealLuksPassphrase` /
`OpenLuksPassphrase` no longer exist.** Their sole purpose was keeping secrets
from the relaying gateway, and [spec 41](../../../docs/content/06-specs/41-gateway-removal.md)
deletes the gateway tier. The agent's mTLS now terminates at control, which is
the only party that could ever have opened those blobs.

**What survives the deletion, because the relay was never its reason:**

- **At-rest encryption** — `SealWithAAD` / `OpenWithAAD` (AES-256-GCM), documented
  above. A different primitive from the public-key `seal` path.
- **The context AAD binding — for LUKS, identically; for LPS, NOT identically.**
  This is stated precisely because an earlier draft got it wrong.
  - **LUKS:** transport bound `device|action` under a LUKS domain, and the at-rest
    path already binds `SecretAAD(device, action, "luks")`. Same shape, nothing lost.
  - **LPS:** transport bound `device|action|username`; the at-rest path binds
    `SecretAAD(device, action, "lps")` — **no username, deliberately.** ADR 0009
    records the choice: *"a within-action username swap is a minor residual inside
    a single trusted rotation batch."* So the username component does not move to
    at-rest — it simply ends.

  What that costs is narrow. It is **not** a confidentiality hole: anyone
  authorised to call `GetDeviceLpsPasswords` for a device already receives every
  username's password on it, so there is no per-username boundary to bypass. What
  ends is an **end-to-end correctness check** — control's unseal used to verify
  that the password it was about to store under `alice` was the one the agent
  generated for `alice`. Nothing checks that association now, which makes a
  zip-mismatch bug in a multi-account rotation batch silent.
- **Domain separation** between LPS and LUKS, so a ciphertext written under one
  domain never opens under the other.

The agent now sends these secrets over the direct mTLS stream and control
encrypts them at rest on receipt.

## Certificates: CSRs, pins, and CA continuity

<!-- docref: begin src=crypto/csr.go#GenerateCSR:4a9d84de,crypto/csr.go#GenerateCSRFromKey:698f4840 -->
`GenerateCSR` creates the agent's ECDSA P-256 key pair and a CSR that
deliberately carries **no SANs**: agent certificates are client certs,
identified by the device ID the control server writes into the issued cert —
the CA rejects any CSR that requests subject alternative names, so including
one fails registration immediately. The hostname goes in the CN only for
operator debuggability (the CA discards it). `GenerateCSRFromKey` builds the
same SAN-free shape for renewal, reusing the existing key pair.
<!-- docref: end -->

<!-- docref: begin src=crypto/cert.go#VerifyCAContinuity:30b656cc,crypto/cert.go#CAFingerprintFromPEM:5a8bdd28 -->
At renewal the agent guards its trust anchor with `VerifyCAContinuity`: a
returned CA must be byte-identical to the enrolled one, or cross-signed by
it. An unrelated CA is refused — that is exactly the trust-anchor swap a
compromised or MITM'd control origin would attempt — and a hard CA swap
requires re-enrollment, never silent adoption over the renewal channel.
`CAFingerprintFromPEM` computes the lowercase-hex SHA-256 of the CA's DER
bytes, matching what an operator derives out-of-band (`openssl x509 -outform
DER | sha256sum`), which is what the optional enrollment CA-pin compares
against.
<!-- docref: end -->

{% callout type="info" title="Reference" %}
Signatures over server-originated *commands* (actions, queries, LUKS
revocations) live in the `verify` package — see
[Agent client & signed commands](/concepts/client).
{% /callout %}

## Related

- [Agent client & signed commands](/concepts/client) — where these
  primitives are used on the wire.
<!-- docref: begin src=crypto/aead.go#ErrAADRequired:c7997fd7 -->
- [Errors](/concepts/errors) — sentinel errors like `ErrAADRequired` are
  matched with `errors.Is`.
<!-- docref: end -->
