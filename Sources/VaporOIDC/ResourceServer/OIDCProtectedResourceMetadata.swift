#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Vapor
import VaporOIDCCore

/// Serves the OAuth 2.0 Protected Resource Metadata document.
///
/// MCP clients use this document to discover the authorization server.
public struct OIDCProtectedResourceMetadata: RouteCollection, Sendable {
    /// The resource identifier of this server.
    public let resource: String

    /// The authorization servers that can issue tokens for this resource.
    public let authorizationServers: [String]

    /// The scopes this resource understands.
    public let scopesSupported: [String]

    /// Creates a metadata route.
    public init(
        resource: String,
        authorizationServers: [String],
        scopesSupported: [String]
    ) {
        self.resource = resource
        self.authorizationServers = authorizationServers
        self.scopesSupported = scopesSupported
    }

    public func boot(routes: any RoutesBuilder) async throws {
        // The well-known endpoint lives at the root of the resource.
        routes.get(".well-known", "oauth-protected-resource", use: self.metadata)
    }

    private func metadata(_ request: Request) async throws -> Response {
        // Build the RFC 9728 document.
        let document = MetadataDocument(
            resource: self.resource,
            authorizationServers: self.authorizationServers,
            scopesSupported: self.scopesSupported,
            bearerMethodsSupported: ["header"]
        )
        let data = try JSONEncoder().encode(document)

        var response = Response(status: .ok, body: .init(data: data))
        response.headers.contentType = HTTPMediaType.json
        return response
    }

    private struct MetadataDocument: Codable {
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
