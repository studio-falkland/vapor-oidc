#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import HTTPTypes
import Testing
import Vapor
import VaporTesting
@testable import VaporOIDC
@testable import VaporOIDCCore

private struct AuthenticatorUser: Authenticatable {
    let subject: String
}

@Suite("OIDCSessionAuthenticator")
struct OIDCSessionAuthenticatorTests {
    private func makeOIDC(
        restore: @escaping @Sendable (OIDCSubject, Request) async throws -> AuthenticatorUser?
    ) -> OIDC<AuthenticatorUser> {
        let provider = FakeOIDCProvider(
            configuration: OIDCConfiguration(
                issuer: URL(string: "https://issuer.example")!,
                clientID: "client",
                redirectURI: URL(string: "https://client.example/callback")!
            ),
            discovery: OIDCDiscovery(
                issuer: "https://issuer.example",
                authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
                tokenEndpoint: URL(string: "https://issuer.example/token")!,
                jwksURI: URL(string: "https://issuer.example/jwks")!
            ),
            identity: OIDCIdentity(
                subject: OIDCSubject(
                    issuer: "https://issuer.example",
                    subject: "123"
                ),
                email: nil,
                emailVerified: nil,
                name: nil,
                preferredUsername: nil,
                picture: nil,
                claims: OIDCClaims(),
                tokens: OIDCTokens(
                    accessToken: "access",
                    refreshToken: nil,
                    idToken: nil,
                    tokenType: "Bearer",
                    expiresAt: nil,
                    scope: nil
                )
            )
        )
        return OIDC<AuthenticatorUser>(
            provider: provider,
            resolver: .init(
                resolve: { identity, _ in
                    AuthenticatorUser(subject: identity.subject.subject)
                },
                restore: restore
            )
        )
    }

    @Test
    func skipsWithoutSessionMiddleware() async throws {
        let oidc = self.makeOIDC { subject, _ in
            AuthenticatorUser(subject: subject.subject)
        }

        try await withApp { app in
            app.middleware.use(oidc.sessionAuthenticator)
            app.get("me") { request in
                request.auth.get(AuthenticatorUser.self)?.subject ?? "anonymous"
            }

            try await app.testing { client in
                let response = try await client.get("me")
                #expect(try await response.body.requireString() == "anonymous")
            }
        }
    }

    @Test
    func clearsSessionWhenRestoreReturnsNil() async throws {
        let oidc = self.makeOIDC { _, _ in nil }

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)

            app.get("set") { request in
                OIDCSession().store(
                    subject: OIDCSubject(
                        issuer: "https://issuer.example",
                        subject: "123"
                    ),
                    idToken: nil,
                    for: request
                )
                return "ok"
            }
            app.get("me") { request in
                request.auth.get(AuthenticatorUser.self)?.subject ?? "anonymous"
            }

            try await app.testing { client in
                let set = try await client.get("set")
                let cookies = try #require(set.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let response = try await client.get("me", headers: headers)
                #expect(try await response.body.requireString() == "anonymous")
            }
        }
    }
}
