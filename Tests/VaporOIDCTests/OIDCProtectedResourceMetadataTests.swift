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

@Suite("OIDCProtectedResourceMetadata")
struct OIDCProtectedResourceMetadataTests {
    @Test
    func returnsMetadata() async throws {
        let metadata = OIDCProtectedResourceMetadata(
            resource: "https://mcp.example.com",
            authorizationServers: ["https://issuer.example"],
            scopesSupported: ["mcp:tools"]
        )

        try await withApp { app in
            try await app.register(collection: metadata)

            try await app.testing { client in
                let response = try await client.get(
                    ".well-known/oauth-protected-resource"
                )
                #expect(response.status == .ok)

                var body = response.body
                let data = try await body.collect() ?? Data()
                let document = try JSONDecoder().decode(Metadata.self, from: data)

                #expect(document.resource == "https://mcp.example.com")
                #expect(document.authorizationServers == ["https://issuer.example"])
                #expect(document.scopesSupported == ["mcp:tools"])
                #expect(document.bearerMethodsSupported == ["header"])
            }
        }
    }

    private struct Metadata: Decodable {
        let resource: String
        let authorizationServers: [String]
        let scopesSupported: [String]
        let bearerMethodsSupported: [String]

        enum CodingKeys: String, CodingKey {
            case resource
            case authorizationServers = "authorization_servers"
            case scopesSupported = "scopes_supported"
            case bearerMethodsSupported = "bearer_methods_supported"
        }
    }
}
