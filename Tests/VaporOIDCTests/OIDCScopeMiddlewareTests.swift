#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
import Vapor
import VaporTesting
@testable import VaporOIDC
@testable import VaporOIDCCore

@Suite("OIDCScopeMiddleware")
struct OIDCScopeMiddlewareTests {
    @Test
    func allowsTokenWithScope() async throws {
        try await withApp { app in
            let group = app.grouped(
                FakeBearerMiddleware(scopes: ["mcp:tools"]),
                OIDCScopeMiddleware("mcp:tools")
            )
            group.get("tools") { _ in "ok" }

            try await app.testing { client in
                let response = try await client.get("tools")
                #expect(response.status == .ok)
            }
        }
    }

    @Test
    func rejectsTokenWithoutScope() async throws {
        try await withApp { app in
            let group = app.grouped(
                FakeBearerMiddleware(scopes: ["mcp:read"]),
                OIDCScopeMiddleware("mcp:tools")
            )
            group.get("tools") { _ in "ok" }

            try await app.testing { client in
                let response = try await client.get("tools")
                #expect(response.status == .forbidden)
            }
        }
    }
}

private struct FakeBearerMiddleware: Middleware {
    let scopes: Set<String>

    init(scopes: Set<String>) {
        self.scopes = scopes
    }

    func respond(
        to request: Request,
        chainingTo next: any Responder
    ) async throws -> Response {
        request.auth.login(
            OIDCAccessToken(
                subject: OIDCSubject(
                    issuer: "https://issuer.example",
                    subject: "123"
                ),
                clientID: nil,
                scopes: self.scopes,
                audience: [],
                expiresAt: nil,
                claims: OIDCClaims()
            )
        )
        return try await next.respond(to: request)
    }
}
