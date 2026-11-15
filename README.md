<p align="center">
  <a href="https://swift.org"><img src="https://img.shields.io/badge/Swift-6.4+-F05138?logo=swift&logoColor=white" alt="Swift 6.4+"></a>
  <a href="https://swift.org/package-manager"><img src="https://img.shields.io/badge/SPM-compatible-4BC51D?logo=swift&logoColor=white" alt="SPM Compatible"></a>
  <a href="https://github.com/vapor/vapor"><img src="https://img.shields.io/badge/Vapor-5-6DBEEB?logo=vapor&logoColor=white" alt="Vapor 5"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/License-EUPL--1.2-blue.svg" alt="License: EUPL-1.2"></a>
</p>

## Introduction

`vapor-oidc` lets your Vapor app sign users in with any OpenID Connect
provider — Google, Microsoft, Okta, Keycloak, Auth0, and so on — while keeping
the login in the user model you already have.

It handles the browser round-trip, validates the provider's response, restores
the signed-in user on later requests, and supports logging out through the
provider. You decide how users are stored and what happens when someone signs
in for the first time.

## Installation

Add the package to your Vapor project's `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/vapor/vapor.git", from: "5.0.0-beta.4"),
    .package(url: "https://github.com/studio-falkland/vapor-oidc", branch: "main"),
],
targets: [
    .target(name: "App", dependencies: [
        .product(name: "Vapor", package: "vapor"),
        .product(name: "VaporOIDC", package: "vapor-oidc"),
    ]),
]
```

## Quick start

Create an `OIDC` holder in `configure`, add the session middleware and the OIDC
session authenticator, and register the routes under a group:

```swift
import Vapor
import VaporOIDC

let configuration = OIDCConfiguration(
    issuer: URL(string: "https://accounts.example.com")!,
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: URL(string: "https://app.example.com/auth/callback")!
)

let oidc = app.oidc(
    configuration: configuration,
    resolver: .init(
        resolve: { identity, request in
            // Find or create the application's user.
            try await User.findOrCreate(from: identity, on: request)
        },
        restore: { subject, request in
            // Restore the user from the stable iss + sub pair.
            try await User.find(by: subject, on: request)
        }
    )
)

app.middleware.use(app.sessionsMiddleware)
app.middleware.use(oidc.sessionAuthenticator)
try await app.grouped("auth").register(collection: oidc)
```

The holder registers:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/login` | Starts the authorization code flow |
| `GET` | `/auth/callback` | Handles the authorization response |
| `POST` | `/auth/logout` | Clears the session and starts RP-initiated logout |

## Protecting routes

`oidc.sessionAuthenticator` logs the user into Vapor's request authentication
store. Read it with the standard Vapor API:

```swift
app.get("me") { request in
    let user = try request.auth.require(User.self)
    return user
}
```

Use `request.auth.get(User.self)` when authentication is optional:

```swift
app.get("maybe-me") { request in
    guard let user = request.auth.get(User.self) else {
        return "anonymous"
    }
    return "hello, \(user.name)"
}
```

`require` throws `Abort(.unauthorized)` when no user is authenticated.

The authenticator must run after `SessionsMiddleware`:

```swift
app.middleware.use(app.sessionsMiddleware)
app.middleware.use(oidc.sessionAuthenticator)
```

To protect only a subset of routes, add the authenticator to a group instead of
globally:

```swift
let protected = app.grouped(oidc.sessionAuthenticator)
protected.get("me") { request in
    try request.auth.require(User.self)
}
```

## MCP / resource server

When your Vapor app is an MCP server (or any OAuth 2.1 resource server), clients
send a bearer token instead of a session cookie. Create a separate
`OIDCResourceServer`:

```swift
let resource = app.oidcResourceServer(
    configuration: .init(
        issuer: URL(string: "https://accounts.example.com")!,
        audience: "https://mcp.example.com",
        requiredScopes: ["mcp:tools"],
        tokenValidation: .automatic,
        introspectionClientID: "mcp-server",
        introspectionClientSecret: "..."
    ),
    resolver: .init { token, request in
        try await User.find(by: token.subject, on: request)
    }
)

let mcp = app.grouped(resource.bearerAuthenticator)
mcp.get("tools") { request in
    let user = try request.auth.require(User.self)
    return try await tools(for: user)
}
```

The holder registers `/.well-known/oauth-protected-resource` automatically when
you register it:

```swift
try await app.register(collection: resource)
```

`tokenValidation` can be `.jwt`, `.introspection`, or `.automatic`. Automatic
validates JWTs with the provider's JWKS and introspects opaque tokens. Both
Authentik and Zitadel issue JWT access tokens and expose an introspection
endpoint.

Per-route scopes:

```swift
let tools = mcp.grouped(OIDCScopeMiddleware("mcp:tools"))
tools.get("tools") { request in
    let user = try request.auth.require(User.self)
    ...
}
```

Or inside a handler:

```swift
try request.requireScope("mcp:tools")
```

Missing or invalid tokens return `401` with a `WWW-Authenticate` challenge that
points at the protected-resource metadata. Insufficient scopes return `403`.

## Configuration with Swift Configuration

Vapor 5 exposes a `ConfigReader` on the application. The default reader reads
command-line arguments and environment variables, so the OIDC settings can live
in the environment without any extra setup:

```env
OIDC_ISSUER=https://accounts.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/auth/callback
```

The environment variable names are derived from the configuration keys by
uppercasing them and joining the components with underscores. For example,
`oidc.clientID` becomes `OIDC_CLIENT_ID`.

Read the values in `configure`:

```swift
import Vapor
import VaporOIDC

func oidcConfiguration(from app: Application) throws -> OIDCConfiguration {
    let issuer = try app.configReader.requiredString(forKey: "oidc.issuer")
    let clientID = try app.configReader.requiredString(forKey: "oidc.clientID")
    let redirectURI = try app.configReader.requiredString(forKey: "oidc.redirectURI")

    guard let issuerURL = URL(string: issuer),
          let redirectURL = URL(string: redirectURI) else {
        throw Abort(.internalServerError, reason: "Invalid OIDC configuration.")
    }

    return OIDCConfiguration(
        issuer: issuerURL,
        clientID: clientID,
        clientSecret: app.configReader.string(
            forKey: "oidc.clientSecret",
            isSecret: true
        ),
        redirectURI: redirectURL
    )
}

let configuration = try oidcConfiguration(from: app)
let oidc = app.oidc(configuration: configuration, resolver: resolver)
```

`isSecret: true` tells Swift Configuration to treat the client secret as
sensitive in access reports and logs. The same keys work with any custom
`ConfigReader`, including file-based providers, so the example is not tied to
environment variables.

## User-model agnosticism

The library never assumes a user table. `OIDCUserResolver<User>` is the only
hook:

```swift
public struct OIDCUserResolver<User: Authenticatable>: Sendable {
    public let resolve: @Sendable (OIDCIdentity, Request) async throws -> User
    public let restore: @Sendable (OIDCSubject, Request) async throws -> User?
}
```

- `resolve` runs after a successful login. It receives the merged ID Token and
  UserInfo claims and returns the application's `User`.
- `restore` runs on each request. It receives the stable `OIDCSubject` and
  returns the user, or `nil` to log the user out.

The application decides whether to auto-create users, how to map claims to
fields and roles, and whether to persist access or refresh tokens.

### Fluent example

The package does not depend on Fluent, but a Fluent model works naturally:

```swift
final class User: Model, Authenticatable {
    static let schema = "users"

    @ID(key: .id) var id: UUID?
    @Field(key: "oidc_issuer") var oidcIssuer: String
    @Field(key: "oidc_subject") var oidcSubject: String
    @OptionalField(key: "email") var email: String?

    init() {}
}

let resolver = OIDCUserResolver<User>(
    resolve: { identity, request in
        if let user = try await User.query(on: request.db)
            .filter(\.$oidcIssuer == identity.subject.issuer)
            .filter(\.$oidcSubject == identity.subject.subject)
            .first() {
            return user
        }

        let user = User()
        user.oidcIssuer = identity.subject.issuer
        user.oidcSubject = identity.subject.subject
        user.email = identity.email
        try await user.save(on: request.db)
        return user
    },
    restore: { subject, request in
        try await User.query(on: request.db)
            .filter(\.$oidcIssuer == subject.issuer)
            .filter(\.$oidcSubject == subject.subject)
            .first()
    }
)
```

> `request.db` is provided by `vapor/fluent`. The OIDC package itself only
> requires `User: Authenticatable`.

## Security

The library follows the OpenID Connect Basic Client Implementer's Guide and
RFC 9700:

- PKCE `S256` only. Never `plain`. Never fall back.
- `state` + `nonce` + PKCE together. `state` is consumed once.
- Exact redirect URI matching. No wildcards. No open redirectors.
- The issuer is stored in `OIDCState` and validated in the callback and the ID
  Token.
- ID Token validation covers the signature, `iss`, `aud`, `azp`, `exp`,
  `iat`/`nbf`, `nonce`, and `at_hash`.
- `alg: none`, HMAC algorithms, and `x5u`/`x5c`/`jku`/`jwk` header parameters
  are rejected.
- UserInfo `sub` must equal the ID Token `sub` before claims are merged.
- `iss` + `sub` is the only stable identity. Never key users on email, phone,
  or username. `emailVerified` is exposed for the application to enforce.
- HTTPS is required for discovery, authorization, token, JWKS, UserInfo, and
  end-session endpoints.
- Tokens are never placed in query strings. UserInfo uses
  `Authorization: Bearer`.
- Redirects use `303 See Other`.
- The ID token is stored in the session only for RP-initiated logout, behind
  `storeIDTokenForLogout`.
- Refresh token rotation is handled by the application: if the provider returns
  a new refresh token, persist it. The library validates `iss` and `aud` on a
  refreshed ID Token; the application should verify the subject has not changed.

### Session configuration

Use a server-side session driver in production and configure the session cookie
with `Secure`, `HttpOnly`, and `SameSite=Lax`. The default `MemorySessions`
driver is intended for development and tests.

## Options

```swift
let oidc = OIDC<User>(
    provider: provider,
    resolver: resolver,
    options: OIDCOptions(
        defaultRedirectAfterLogin: "/",
        postLogoutRedirectURI: URL(string: "https://app.example.com/")!,
        redirectQueryParameter: "redirect",
        storeIDTokenForLogout: true,
        allowedRedirectOrigins: ["https://app.example.com"]
    )
)
```

`OIDCOptions.sanitizeRedirect(_:)` allows relative paths and absolute URLs whose
origin is in `allowedRedirectOrigins`. Everything else falls back to
`defaultRedirectAfterLogin`.

## Testing

Use `FakeOIDCProvider` and `MockOIDCHTTPClient` from `VaporOIDCCore`:

```swift
let provider = FakeOIDCProvider(
    configuration: configuration,
    discovery: discovery,
    identity: identity
)

let oidc = OIDC<User>(provider: provider, resolver: resolver)
```

The fake records authorization requests, exchanged codes, refresh tokens,
UserInfo requests, and logout requests.

## Out of scope

v1 deliberately does not implement:

- Implicit and hybrid flows.
- Resource Owner Password Credentials.
- `max_age`, `auth_time`, and `acr_values`.
- `prompt=none` and silent authentication.
- The `claims` request parameter.
- JAR (`request`/`request_uri`) and PAR.
- DPoP and mTLS.
- Back-channel and front-channel logout.
- Dynamic client registration.
- Native and browser-based client profiles.
- Automatic token refresh.

## Running tests

```bash
swift test
```

## Authors

This library is developed by Lei Nelissen at Studio Falkland.

## License

Licensed under the **European Union Public Licence v. 1.2 (EUPL-1.2)**. See
[`LICENSE.md`](LICENSE.md) for the full text.
