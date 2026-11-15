#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging

/// Fetches, caches, and verifies against an OpenID Connect JWKS.
actor OIDCJWKSLoader {
    private let discoveryLoader: OIDCDiscoveryLoader
    private let cacheDuration: TimeInterval
    private let requireHTTPS: Bool
    private let httpClient: any OIDCHTTPClient
    private let logger: Logger

    private var cachedJWKS: JWKS?
    private var fetchedAt: Date?
    private var keys = JWTKeyCollection()

    init(
        discoveryLoader: OIDCDiscoveryLoader,
        cacheDuration: TimeInterval,
        requireHTTPS: Bool,
        httpClient: any OIDCHTTPClient,
        logger: Logger
    ) {
        self.discoveryLoader = discoveryLoader
        self.cacheDuration = cacheDuration
        self.requireHTTPS = requireHTTPS
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Returns the cached key collection, refreshing it when stale.
    func keyCollection() async throws -> JWTKeyCollection {
        if let fetchedAt,
           Date().timeIntervalSince(fetchedAt) < self.cacheDuration {
            return self.keys
        }
        return try await self.refresh()
    }

    /// Refreshes the JWKS and returns the new key collection.
    func refresh() async throws -> JWTKeyCollection {
        // Fetch the JWKS from the provider.
        let discovery = try await self.discoveryLoader.load()
        try OIDCClaimValidation.requireHTTPS(
            discovery.jwksURI,
            enabled: self.requireHTTPS
        )
        let response = try await self.httpClient.send(
            OIDCHTTPRequest(method: "GET", url: discovery.jwksURI)
        )
        guard response.statusCode == 200 else {
            throw OIDCError.discoveryFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        // Decode the keys and replace the key collection.
        let jwks: JWKS
        do {
            jwks = try JSONDecoder().decode(JWKS.self, from: response.body)
        } catch {
            throw OIDCError.invalidDiscoveryDocument("Unable to decode the JWKS: \(error)")
        }

        let keys = JWTKeyCollection()
        try await keys.add(jwks: jwks)
        self.keys = keys
        self.cachedJWKS = jwks
        self.fetchedAt = Date()
        return keys
    }

    /// Verifies a token, refreshing the JWKS once on failure.
    func verify<Payload: JWTPayload>(
        _ token: String,
        as payload: Payload.Type
    ) async throws -> Payload {
        let keys = try await self.keyCollection()
        do {
            return try await keys.verify(token, as: Payload.self)
        } catch {
            let refreshed = try await self.refresh()
            return try await refreshed.verify(token, as: Payload.self)
        }
    }

    /// Returns whether the JWKS has more than one key.
    func requiresKeyIdentifier() async throws -> Bool {
        _ = try await self.keyCollection()
        return (self.cachedJWKS?.keys.count ?? 0) > 1
    }
}
