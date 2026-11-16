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

private struct TestUser: Authenticatable {
    let subject: String
}

@Suite("OIDCLogin")
struct OIDCLoginTests {
    private func configuration() -> OIDCConfiguration {
        OIDCConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            clientID: "client",
            clientSecret: "secret",
            redirectURI: URL(string: "https://client.example/auth/callback")!
        )
    }

    private func discovery() -> OIDCDiscovery {
        OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            userinfoEndpoint: URL(string: "https://issuer.example/userinfo")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!,
            endSessionEndpoint: URL(string: "https://issuer.example/logout")!,
            codeChallengeMethodsSupported: ["S256"]
        )
    }

    private func identity() -> OIDCIdentity {
        OIDCIdentity(
            subject: OIDCSubject(
                issuer: "https://issuer.example",
                subject: "123"
            ),
            email: "user@example.com",
            emailVerified: true,
            name: "User",
            preferredUsername: nil,
            picture: nil,
            claims: OIDCClaims([
                "sub": .string("123"),
                "email": .string("user@example.com"),
            ]),
            tokens: OIDCTokens(
                accessToken: "access",
                refreshToken: "refresh",
                idToken: "id",
                tokenType: "Bearer",
                expiresAt: nil,
                scope: "openid"
            )
        )
    }

    private func makeOIDC(
        options: OIDCOptions = .init(),
        stateStore: any OIDCStateStore = SessionOIDCStateStore()
    ) -> OIDC<TestUser> {
        let provider = FakeOIDCProvider(
            configuration: self.configuration(),
            discovery: self.discovery(),
            identity: self.identity()
        )
        return OIDC<TestUser>(
            provider: provider,
            resolver: .init(
                resolve: { identity, _ in
                    TestUser(subject: identity.subject.subject)
                },
                restore: { subject, _ in
                    TestUser(subject: subject.subject)
                }
            ),
            options: options,
            stateStore: stateStore
        )
    }

    private func login(
        _ client: any TestClient,
        query: String = ""
    ) async throws -> (cookie: String, state: String) {
        // Start the flow and capture the session cookie and state value.
        let response = try await client.get(URI(string: "auth/login\(query)"))
        let cookies = try #require(response.headers.setCookie)
        let cookie = try #require(cookies["vapor-session"])
        let location = try #require(response.headers[.location])
        let state = try #require(
            URLComponents(string: location)?
                .queryItems?
                .first(where: { $0.name == "state" })?
                .value
        )
        return (cookie.string, state)
    }

    private func callbackHeaders(_ cookie: String) -> HTTPFields {
        var headers = HTTPFields()
        headers[.cookie] = "vapor-session=\(cookie)"
        return headers
    }

    @Test
    func loginRedirectsToProvider() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let response = try await client.get("auth/login")
                #expect(response.status == .seeOther)

                let location = try #require(response.headers[.location])
                #expect(location.contains("https://provider.example/authorize"))
                #expect(location.contains("state="))
                #expect(location.contains("code_challenge="))
            }
        }
    }

    @Test
    func callbackLogsInUser() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let login = try await client.get("auth/login")
                let cookies = try #require(login.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])
                let location = try #require(login.headers[.location])
                let state = try #require(
                    URLComponents(string: location)?
                        .queryItems?
                        .first(where: { $0.name == "state" })?
                        .value
                )

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let callback = try await client.get(
                    "auth/callback?code=code&state=\(state)",
                    headers: headers
                )

                #expect(callback.status == .seeOther)
                #expect(callback.headers[.location] == "/")
            }
        }
    }

    @Test
    func callbackRejectsUnsafeRedirectTarget() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                // "/%5Cevil.example" decodes to "/\\evil.example", which
                // browsers would follow as a protocol-relative redirect.
                let login = try await client.get(
                    "auth/login?redirect=/%5Cevil.example"
                )
                let cookies = try #require(login.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])
                let location = try #require(login.headers[.location])
                let state = try #require(
                    URLComponents(string: location)?
                        .queryItems?
                        .first(where: { $0.name == "state" })?
                        .value
                )

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let callback = try await client.get(
                    "auth/callback?code=code&state=\(state)",
                    headers: headers
                )

                #expect(callback.status == .seeOther)
                #expect(callback.headers[.location] == "/")
            }
        }
    }

    @Test
    func callbackRejectsProviderError() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let response = try await client.get(
                    "auth/callback?error=access_denied&error_description=denied"
                )
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test
    func callbackRejectsMissingCode() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let response = try await client.get(
                    "auth/callback?state=anything"
                )
                #expect(response.status == .badRequest)
            }
        }
    }

    @Test
    func callbackRejectsMissingState() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let response = try await client.get("auth/callback?code=code")
                #expect(response.status == .badRequest)
            }
        }
    }

    @Test
    func callbackRejectsUnknownState() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let response = try await client.get(
                    "auth/callback?code=code&state=unknown"
                )
                #expect(response.status == .badRequest)
            }
        }
    }

    @Test
    func callbackRejectsReplayedState() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let login = try await self.login(client)
                let headers = self.callbackHeaders(login.cookie)

                let first = try await client.get(
                    "auth/callback?code=code&state=\(login.state)",
                    headers: headers
                )
                #expect(first.status == .seeOther)

                let second = try await client.get(
                    "auth/callback?code=code&state=\(login.state)",
                    headers: headers
                )
                #expect(second.status == .badRequest)
            }
        }
    }

    @Test
    func callbackRejectsExpiredState() async throws {
        let oidc = self.makeOIDC(
            stateStore: SessionOIDCStateStore(maximumAge: -1)
        )

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let login = try await self.login(client)
                let response = try await client.get(
                    "auth/callback?code=code&state=\(login.state)",
                    headers: self.callbackHeaders(login.cookie)
                )
                #expect(response.status == .badRequest)
            }
        }
    }

    @Test
    func callbackRejectsIssuerMismatch() async throws {
        let oidc = self.makeOIDC()

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let login = try await self.login(client)
                let response = try await client.get(
                    "auth/callback?code=code&state=\(login.state)&iss=https://evil.example",
                    headers: self.callbackHeaders(login.cookie)
                )
                #expect(response.status == .internalServerError)
            }
        }
    }
}
