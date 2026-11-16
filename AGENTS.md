# vapor-oidc — Agent Guide

## What this is

A small OpenID Connect Relying Party library for Vapor 5. It implements the
Authorization Code Flow with PKCE `S256` and stores the login against whatever
user model the application chooses. It does not depend on Fluent.

## Primary reference

**OpenID Connect Basic Client Implementer's Guide 1.0**
<https://openid.net/specs/openid-connect-basic-1_0.html>

Use this as the default checklist for the code flow, ID Token validation,
UserInfo, and claim stability. When it conflicts with the normative specs, the
normative specs win:

- OpenID Connect Core 1.0 (errata set 2): <https://openid.net/specs/openid-connect-core-1_0.html>
- RFC 9700 (OAuth 2.0 Security BCP): <https://www.rfc-editor.org/rfc/rfc9700.html>
- OpenID Connect Discovery 1.0: <https://openid.net/specs/openid-connect-discovery-1_0.html>
- OpenID Connect RP-Initiated Logout 1.0: <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>
- RFC 7636 (PKCE): <https://www.rfc-editor.org/rfc/rfc7636.html>
- RFC 9207 (issuer identification): <https://www.rfc-editor.org/rfc/rfc9207.html>

## Architecture

- Products: `VaporOIDCCore` (depends on Vapor only for `URLEncodedFormEncoder`)
  and `VaporOIDC` (Vapor adapter, re-exports the core).
- `OIDCProvider` is the protocol. `OIDCClient` is the production actor.
  `FakeOIDCProvider` and `MockOIDCHTTPClient` live in `Testing/`.
- `OIDC<User>` owns the provider, resolver, state store, session, and routes.
- `OIDCUserResolver<User>` is the only user-model hook: `resolve` on login,
  `restore` from `OIDCSubject` on subsequent requests.
- State, nonce, PKCE verifier, and `OIDCSubject` live in Vapor sessions.
- The ID token is stored only for RP-initiated logout, behind
  `storeIDTokenForLogout`.
- `OIDCResourceServer<User>` is the OAuth 2.1 resource-server surface. It
  validates bearer tokens (JWT or introspection), resolves the user, and serves
  `/.well-known/oauth-protected-resource`.

## Security invariants

- PKCE `S256` only. Never `plain`. Never fall back.
- `state` + `nonce` + PKCE together. `state` is consumed once.
- Exact redirect URI matching. No wildcards. No open redirectors.
- Store the issuer in `OIDCState`. Validate the `iss` query parameter if
  present and the ID Token `iss` exactly.
- Validate the ID Token: signature, `iss`, `aud` (contains the client ID and no
  untrusted extra audiences), `azp` if present, `exp`, `iat`/`nbf` with clock
  skew, `nonce`, and `at_hash` if present.
- Reject `alg: none`, HMAC algorithms, and `x5u`/`x5c`/`jku`/`jwk` header
  parameters.
- UserInfo `sub` must equal the ID Token `sub` before merging claims.
- `iss` + `sub` is the only stable identity. Never key users on email, phone,
  or username. Expose `emailVerified`.
- HTTPS only for discovery, authorization, token, JWKS, UserInfo, and
  end-session endpoints.
- No tokens in query strings. UserInfo uses `Authorization: Bearer`.
- No implicit flow. No ROPC.
- `303 See Other` for redirects. Never `307`.
- Server-side sessions recommended. `Secure`, `HttpOnly`, `SameSite=Lax`
  cookies.
- Refresh token rotation: if the provider returns a new refresh token, the app
  must persist it. Validate `iss` and `aud` if an ID Token is returned on
  refresh; the app should verify the returned subject has not changed.
- RP-Initiated Logout 1.0 for logout.
- Resource-server tokens: validate `iss`, `aud`, `exp`, `nbf`, and the
  signature; reject `none`/HMAC; enforce scopes; never accept ID tokens as
  access tokens.
- Introspection results are cached briefly and bounded by the token expiry.

## Development practices

1. Validate with diagnostics, not builds.
2. Prefer built-in tools.
3. Reuse Vapor, JWTKit, and the standard library.
4. Plan, then wait.
5. Comment in blocks.
6. Prefer `FoundationEssentials` with a guarded import.
7. Keep this file current.
8. The user edits alongside you. Re-read before editing.

## Commands

- `swift test`
- `swift build` only when diagnostics and tests can't answer.

## Coverage

Run the suite with instrumentation, then generate a per-file report:

```bash
swift test --enable-code-coverage

xcrun llvm-cov report \
  -instr-profile .build/debug/codecov/default.profdata \
  -object .build/debug/VaporOIDCCoreTests.xctest/Contents/MacOS/VaporOIDCCoreTests \
  -object .build/debug/VaporOIDCTests.xctest/Contents/MacOS/VaporOIDCTests \
  -ignore-filename-regex '(^|/)(Tests|\.build)/'
```

The report reads the default `.build/debug` build directory. The
`-ignore-filename-regex` keeps it to package sources by excluding the test
targets and `.build`. If you need the JSON export (for Codecov or another
service), `swift test --show-codecov-path` prints its path.

CI runs the same report in the macOS job, writes it to the job summary, and
uploads `coverage.txt` as the `coverage` artifact. The Linux job remains a build
and test smoke check. No coverage threshold is enforced.

Coverage is a guide, not a goal. The critical paths are the ID Token validation
matrix, UserInfo subject binding, state handling, and resource-server token
checks. Keep those at full branch coverage.

## Scope boundaries

v1 implements the Authorization Code Flow with PKCE `S256`, `state`, `nonce`,
discovery, JWKS, ID Token validation, UserInfo, a manual refresh helper,
RP-initiated logout, and an OAuth 2.1 resource-server surface for bearer tokens.

Out of scope: implicit/hybrid flows, ROPC, `max_age`/`auth_time`/`acr`,
`prompt=none`, the `claims` parameter, JAR/PAR, DPoP/mTLS, back-channel and
front-channel logout, dynamic client registration, native and browser-based
client profiles, and automatic token refresh.
