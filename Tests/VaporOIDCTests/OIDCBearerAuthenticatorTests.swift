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

private struct BearerUser: Authenticatable {
    let subject: String
}

private actor FakeAccessTokenValidator: OIDCAccessTokenValidator {
    let result: Result<OIDCAccessToken, OIDCError>

    init(result: Result<OIDCAccessToken, OIDCError>) {
        self.result = result
    }

    func validate(_ token: String) async throws -> OIDCAccessToken {
        try self.result.get()
    }
}

@Suite("OIDCBearerAuthenticator")
struct OIDCBearerAuthenticatorTests {
    private func configuration(
        requiredScopes: Set<String> = ["mcp:tools"]
    ) -> OIDCResourceServerConfiguration {
        OIDCResourceServerConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            audience: "https://mcp.example.com",
            requiredScopes: requiredScopes
        )
    }

    private func accessToken(
        scopes: Set<String> = ["mcp:tools"]
    ) -> OIDCAccessToken {
        OIDCAccessToken(
            subject: OIDCSubject(
                issuer: "https://issuer.example",
                subject: "123"
            ),
            clientID: "client",
            scopes: scopes,
            audience: ["https://mcp.example.com"],
            expiresAt: Date().addingTimeInterval(300),
            claims: OIDCClaims()
        )
    }

    private func makeResourceServer(
        validator: any OIDCAccessTokenValidator,
        requiredScopes: Set<String> = ["mcp:tools"]
    ) -> OIDCResourceServer<BearerUser> {
        OIDCResourceServer(
            configuration: self.configuration(requiredScopes: requiredScopes),
            validator: validator,
            resolver: .init { token, _ in
                BearerUser(subject: token.subject.subject)
            }
        )
    }

    @Test
    func authenticatesValidToken() async throws {
        let validator = FakeAccessTokenValidator(
            result: .success(self.accessToken())
        )
        let resource = self.makeResourceServer(validator: validator)

        try await withApp { app in
            let protected = app.grouped(resource.bearerAuthenticator)
            protected.get("me") { request in
                let user = try request.auth.require(BearerUser.self)
                let token = try request.auth.require(OIDCAccessToken.self)
                return "\(user.subject):\(token.scopes.sorted().joined(separator: ","))"
            }

            try await app.testing { client in
                var headers = HTTPFields()
                headers[.authorization] = "Bearer token"
                let response = try await client.get("me", headers: headers)
                #expect(response.status == .ok)
                #expect(try await response.body.requireString() == "123:mcp:tools")
            }
        }
    }

    @Test
    func rejectsMissingToken() async throws {
        let validator = FakeAccessTokenValidator(
            result: .success(self.accessToken())
        )
        let resource = self.makeResourceServer(validator: validator)

        try await withApp { app in
            let protected = app.grouped(resource.bearerAuthenticator)
            protected.get("me") { request in
                try request.auth.require(BearerUser.self).subject
            }

            try await app.testing { client in
                let response = try await client.get("me")
                #expect(response.status == .unauthorized)
                #expect(
                    response.headers[.wwwAuthenticate]?
                        .contains("resource_metadata") == true
                )
            }
        }
    }

    @Test
    func rejectsInvalidToken() async throws {
        let validator = FakeAccessTokenValidator(
            result: .failure(.invalidAccessToken("bad"))
        )
        let resource = self.makeResourceServer(validator: validator)

        try await withApp { app in
            let protected = app.grouped(resource.bearerAuthenticator)
            protected.get("me") { request in
                try request.auth.require(BearerUser.self).subject
            }

            try await app.testing { client in
                var headers = HTTPFields()
                headers[.authorization] = "Bearer token"
                let response = try await client.get("me", headers: headers)
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test
    func rejectsInsufficientScope() async throws {
        let validator = FakeAccessTokenValidator(
            result: .success(self.accessToken(scopes: []))
        )
        let resource = self.makeResourceServer(validator: validator)

        try await withApp { app in
            let protected = app.grouped(resource.bearerAuthenticator)
            protected.get("me") { request in
                try request.auth.require(BearerUser.self).subject
            }

            try await app.testing { client in
                var headers = HTTPFields()
                headers[.authorization] = "Bearer token"
                let response = try await client.get("me", headers: headers)
                #expect(response.status == .forbidden)
                #expect(
                    response.headers[.wwwAuthenticate]?
                        .contains("insufficient_scope") == true
                )
            }
        }
    }

    @Test
    func rejectsUnknownUser() async throws {
        let validator = FakeAccessTokenValidator(
            result: .success(self.accessToken())
        )
        let resource = OIDCResourceServer<BearerUser>(
            configuration: self.configuration(),
            validator: validator,
            resolver: .init { _, _ in nil }
        )

        try await withApp { app in
            let protected = app.grouped(resource.bearerAuthenticator)
            protected.get("me") { request in
                try request.auth.require(BearerUser.self).subject
            }

            try await app.testing { client in
                var headers = HTTPFields()
                headers[.authorization] = "Bearer token"
                let response = try await client.get("me", headers: headers)
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test
    func registersProtectedResourceMetadata() async throws {
        let resource = self.makeResourceServer(
            validator: FakeAccessTokenValidator(
                result: .success(self.accessToken())
            )
        )

        try await withApp { app in
            try await app.register(collection: resource)

            try await app.testing { client in
                let response = try await client.get(
                    ".well-known/oauth-protected-resource"
                )
                #expect(response.status == .ok)
            }
        }
    }
}
