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

private struct ApplicationUser: Authenticatable {
    let subject: String
}

@Suite("Application+OIDC")
struct ApplicationOIDCTests {
    @Test
    func createsOIDCHolder() async throws {
        try await withApp { app in
            let oidc = app.oidc(
                configuration: OIDCConfiguration(
                    issuer: URL(string: "https://issuer.example")!,
                    clientID: "client",
                    redirectURI: URL(string: "https://client.example/callback")!
                ),
                resolver: .init(
                    resolve: { identity, _ in
                        ApplicationUser(subject: identity.subject.subject)
                    },
                    restore: { subject, _ in
                        ApplicationUser(subject: subject.subject)
                    }
                )
            )

            #expect(oidc.provider.configuration.clientID == "client")
            #expect(
                oidc.provider.configuration.issuer.absoluteString
                    == "https://issuer.example"
            )
        }
    }

    @Test
    func createsResourceServer() async throws {
        try await withApp { app in
            let resource: OIDCResourceServer<ApplicationUser> = app.oidcResourceServer(
                configuration: OIDCResourceServerConfiguration(
                    issuer: URL(string: "https://issuer.example")!,
                    audience: "https://mcp.example.com"
                ),
                resolver: .init { _, _ in nil }
            )

            #expect(
                resource.configuration.audience == "https://mcp.example.com"
            )
        }
    }
}
