#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Logging

/// Fetches and caches an OpenID Connect discovery document.
actor OIDCDiscoveryLoader {
    private let issuer: URL
    private let discoveryURL: URL?
    private let requireHTTPS: Bool
    private let httpClient: any OIDCHTTPClient
    private let logger: Logger
    private var cached: OIDCDiscovery?

    init(
        issuer: URL,
        discoveryURL: URL?,
        requireHTTPS: Bool,
        httpClient: any OIDCHTTPClient,
        logger: Logger
    ) {
        self.issuer = issuer
        self.discoveryURL = discoveryURL
        self.requireHTTPS = requireHTTPS
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Returns the cached document, fetching it on first use.
    func load() async throws -> OIDCDiscovery {
        if let cached {
            return cached
        }

        // Build the discovery URL and require HTTPS.
        let url = self.discoveryURL
            ?? self.issuer.appendingPathComponent(".well-known/openid-configuration")
        try OIDCClaimValidation.requireHTTPS(url, enabled: self.requireHTTPS)

        // Fetch and decode the document.
        let response = try await self.httpClient.send(
            OIDCHTTPRequest(method: "GET", url: url)
        )
        guard response.statusCode == 200 else {
            throw OIDCError.discoveryFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        let discovery: OIDCDiscovery
        do {
            discovery = try JSONDecoder().decode(OIDCDiscovery.self, from: response.body)
        } catch {
            throw OIDCError.invalidDiscoveryDocument(String(describing: error))
        }

        // Require the document to describe the configured issuer.
        try OIDCClaimValidation.validateIssuer(
            discovery.issuer,
            expected: self.issuer.absoluteString
        )

        // Require every endpoint we might use to use HTTPS.
        try self.validateEndpoints(discovery)

        self.cached = discovery
        return discovery
    }

    private func validateEndpoints(_ discovery: OIDCDiscovery) throws {
        try OIDCClaimValidation.requireHTTPS(
            discovery.authorizationEndpoint,
            enabled: self.requireHTTPS
        )
        try OIDCClaimValidation.requireHTTPS(
            discovery.tokenEndpoint,
            enabled: self.requireHTTPS
        )
        try OIDCClaimValidation.requireHTTPS(
            discovery.jwksURI,
            enabled: self.requireHTTPS
        )
        if let userinfoEndpoint = discovery.userinfoEndpoint {
            try OIDCClaimValidation.requireHTTPS(
                userinfoEndpoint,
                enabled: self.requireHTTPS
            )
        }
        if let endSessionEndpoint = discovery.endSessionEndpoint {
            try OIDCClaimValidation.requireHTTPS(
                endSessionEndpoint,
                enabled: self.requireHTTPS
            )
        }
        if let introspectionEndpoint = discovery.introspectionEndpoint {
            try OIDCClaimValidation.requireHTTPS(
                introspectionEndpoint,
                enabled: self.requireHTTPS
            )
        }
    }
}
