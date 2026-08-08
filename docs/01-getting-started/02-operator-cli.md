---
title: Operator CLI
description: Bootstrap OIDC, sign in locally, and operate Power Manage without the hosted web client.
---

# Operator CLI

Build or install the `powermanage` command from this module:

```bash
go install github.com/manchtools/power-manage-sdk/cmd/powermanage@main
```

The first release supports Unix-like operator workstations; Windows support is
out of scope.

<!-- docref: begin src=cmd/powermanage/storage.go#validateServerURL:2e5ba220 -->
Set the control-server URL once. Production URLs must use HTTPS; literal
loopback HTTP is accepted for local development.

```bash
powermanage config set-server https://control.example
```
<!-- docref: end -->

## Bootstrap OIDC

Register a public/native OIDC client at your identity provider with a loopback
redirect such as `http://127.0.0.1:8400/callback`. Then write the provider
request in the contract's ProtoJSON format:

```json
{
  "name": "Company OIDC",
  "slug": "company",
  "providerType": "IDENTITY_PROVIDER_TYPE_OIDC",
  "cliClientId": "powermanage-cli",
  "issuerUrl": "https://idp.example",
  "autoCreateUsers": true,
  "defaultRoleId": "00000000000000000000000001"
}
```

<!-- docref: begin src=cmd/powermanage/main.go#app.bootstrapCommand:2cb480ba -->
On the control host, pipe the single-use token directly to the CLI:

```bash
control bootstrap-admin --output token \
  | powermanage bootstrap oidc --file provider.json --token-stdin
```

The token is spent only on `CreateIdentityProvider`; it is not stored or
converted into a session.
<!-- docref: end -->

## Sign in

<!-- docref: begin src=cmd/powermanage/main.go#newRootCommand:7e75aac9,cmd/powermanage/main.go#app.login:d1bd9b1f,cmd/powermanage/storage.go#writePrivateJSON:1b9a0673,cmd/powermanage/storage.go#readPrivateJSON:36202d81 -->
```bash
powermanage login --provider company
powermanage whoami
```

The CLI binds `127.0.0.1` before opening the browser, owns the PKCE verifier,
checks the returned state, and exchanges the authorization code directly with
the identity provider. Control receives the signed ID token for verification,
but never receives the authorization code, verifier, or IdP access/refresh
tokens. The resulting Power Manage session is stored in the user's private
configuration directory.
<!-- docref: end -->

For an identity provider that requires an exact redirect port:

```bash
powermanage login --provider company --callback-port 8400
```

<!-- docref: begin src=cmd/powermanage/main.go#app.authCommand:1a215758 -->
`powermanage auth token` prints only the server URL, short-lived Power Manage
access token, and expiry for a local Terraform exec-credential integration.
It never prints the refresh token.
<!-- docref: end -->

## Resource commands

<!-- docref: begin src=cmd/powermanage/storage.go#readProtoJSON:ce591b75,cmd/powermanage/main.go#app.enrollmentTokenCommand:6b70d562 -->
Create commands accept the corresponding generated request message as strict
ProtoJSON from a file or stdin. Unknown fields, malformed JSON, and oversized
input fail locally before a request is sent. Responses are ProtoJSON as well.

```bash
powermanage action create --file create-action.json
powermanage action get 01K...
powermanage action list

powermanage assignment create --file create-assignment.json
powermanage assignment list

powermanage enrollment-token create --file create-token.json
powermanage enrollment-token list
powermanage enrollment-token disable 01K...
```

Enrollment-token creation prints the bearer value and CA fingerprint once.
Later `get` and `list` calls cannot recover that bearer value.
<!-- docref: end -->

Use `--file -` to read a ProtoJSON request from stdin. YAML is intentionally
unsupported; the CLI maps the existing wire format directly instead of adding
another schema.
