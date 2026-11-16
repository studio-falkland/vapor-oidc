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

private struct LogoutUser: Authenticatable {
    let subject: String
}

@Suite("OIDCLogout")
struct OIDCLogoutTests {
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
            claims: OIDCClaims(["sub": .string("123")]),
            tokens: OIDCTokens(
                accessToken: "access",
                refreshToken: "refresh",
                idToken: "id-token",
                tokenType: "Bearer",
                expiresAt: nil,
                scope: "openid"
            )
        )
    }

    private func makeProvider() -> FakeOIDCProvider {
        FakeOIDCProvider(
            configuration: self.configuration(),
            discovery: self.discovery(),
            identity: self.identity()
        )
    }

    private func makeOIDC(
        provider: FakeOIDCProvider,
        options: OIDCOptions = .init()
    ) -> OIDC<LogoutUser> {
        OIDC<LogoutUser>(
            provider: provider,
            resolver: .init(
                resolve: { identity, _ in
                    LogoutUser(subject: identity.subject.subject)
                },
                restore: { subject, _ in
                    LogoutUser(subject: subject.subject)
                }
            ),
            options: options
        )
    }

    private func login(_ client: any TestClient) async throws -> String {
        let response = try await client.get("auth/login")
        let cookies = try #require(response.headers.setCookie)
        let cookie = try #require(cookies["vapor-session"])
        let location = try #require(response.headers[.location])
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

        return cookie.string
    }

    private func cookieHeaders(_ cookie: String) -> HTTPFields {
        var headers = HTTPFields()
        headers[.cookie] = "vapor-session=\(cookie)"
        return headers
    }

    @Test
    func logoutRedirectsToProviderEndSession() async throws {
        let provider = self.makeProvider()
        await provider.setLogoutURLResult(URL(string: "https://provider.example/logout")!)
        let oidc = self.makeOIDC(provider: provider)

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let cookie = try await self.login(client)
                let response = try await client.post(
                    "auth/logout",
                    headers: self.cookieHeaders(cookie)
                )

                #expect(response.status == .seeOther)
                #expect(
                    response.headers[.location]
                        == "https://provider.example/logout"
                )
                let logoutRequests = await provider.logoutRequests
                #expect(logoutRequests.count == 1)
                #expect(logoutRequests.first?.idToken == "id-token")
            }
        }
    }

    @Test
    func logoutWithoutStoredIDTokenSkipsProvider() async throws {
        let provider = self.makeProvider()
        await provider.setLogoutURLResult(URL(string: "https://provider.example/logout")!)
        let oidc = self.makeOIDC(
            provider: provider,
            options: OIDCOptions(storeIDTokenForLogout: false)
        )

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let cookie = try await self.login(client)
                let response = try await client.post(
                    "auth/logout",
                    headers: self.cookieHeaders(cookie)
                )

                #expect(response.status == .seeOther)
                #expect(response.headers[.location] == "/")
                let logoutRequests = await provider.logoutRequests
                #expect(logoutRequests.isEmpty)
            }
        }
    }

    @Test
    func logoutFallsBackWhenProviderHasNoEndSession() async throws {
        let provider = self.makeProvider()
        let oidc = self.makeOIDC(provider: provider)

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let cookie = try await self.login(client)
                let response = try await client.post(
                    "auth/logout",
                    headers: self.cookieHeaders(cookie)
                )

                #expect(response.status == .seeOther)
                #expect(response.headers[.location] == "/")
            }
        }
    }

    @Test
    func logoutUsesConfiguredPostLogoutURI() async throws {
        let provider = self.makeProvider()
        let oidc = self.makeOIDC(
            provider: provider,
            options: OIDCOptions(
                postLogoutRedirectURI: URL(string: "https://app.example/bye")!,
                storeIDTokenForLogout: false
            )
        )

        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)
            app.middleware.use(oidc.sessionAuthenticator)
            try await app.grouped("auth").register(collection: oidc)

            try await app.testing { client in
                let cookie = try await self.login(client)
                let response = try await client.post(
                    "auth/logout",
                    headers: self.cookieHeaders(cookie)
                )

                #expect(response.status == .seeOther)
                #expect(response.headers[.location] == "https://app.example/bye")
            }
        }
    }
}
