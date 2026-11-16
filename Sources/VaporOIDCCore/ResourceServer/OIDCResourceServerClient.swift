#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import JWTKit
import Logging

/// The production resource-server client.
public actor OIDCResourceServerClient: OIDCAccessTokenValidator {
    public nonisolated let configuration: OIDCResourceServerConfiguration

    private let httpClient: any OIDCHTTPClient
    private let discoveryLoader: OIDCDiscoveryLoader
    private let jwksLoader: OIDCJWKSLoader
    private var introspectionCache: [String: CachedIntrospection] = [:]

    private struct CachedIntrospection: Sendable {
        let token: OIDCAccessToken
        let expiresAt: Date
    }

    /// Creates a resource-server client.
    public init(
        configuration: OIDCResourceServerConfiguration,
        httpClient: any OIDCHTTPClient,
        logger: Logger = Logger.current
    ) {
        self.configuration = configuration
        self.httpClient = httpClient

        let discoveryLoader = OIDCDiscoveryLoader(
            issuer: configuration.issuer,
            discoveryURL: configuration.discoveryURL,
            requireHTTPS: configuration.requireHTTPS,
            httpClient: httpClient,
            logger: logger
        )
        self.discoveryLoader = discoveryLoader
        self.jwksLoader = OIDCJWKSLoader(
            discoveryLoader: discoveryLoader,
            cacheDuration: configuration.jwksCacheDuration,
            requireHTTPS: configuration.requireHTTPS,
            httpClient: httpClient,
            logger: logger
        )
    }

    public func validate(_ token: String) async throws -> OIDCAccessToken {
        switch self.configuration.tokenValidation {
        case .jwt:
            return try await self.validateJWT(token)
        case .introspection:
            return try await self.introspect(token)
        case .automatic:
            // A JWT has three dot-separated segments; anything else is opaque.
            if Self.looksLikeJWT(token) {
                return try await self.validateJWT(token)
            }
            return try await self.introspect(token)
        }
    }

    // MARK: - JWT validation

    private func validateJWT(_ token: String) async throws -> OIDCAccessToken {
        // Decode the header and reject unsafe algorithms and key references.
        let header = try OIDCJWTHeader.decode(token)
        try header.validate(allowedAlgorithms: self.configuration.allowedAccessTokenAlgorithms)

        // Require a kid when the JWKS has multiple keys.
        if header.kid == nil, try await self.jwksLoader.requiresKeyIdentifier() {
            throw OIDCError.missingJWKSKey(kid: "<missing>")
        }

        // Verify the signature, refreshing the JWKS once on failure.
        let claims: OIDCAccessTokenClaims
        do {
            claims = try await self.jwksLoader.verify(token, as: OIDCAccessTokenClaims.self)
        } catch {
            throw OIDCError.invalidAccessToken(String(describing: error))
        }

        // Validate the issuer, audience, and time-based claims.
        try OIDCClaimValidation.validateIssuer(
            claims.issuer.value,
            expected: self.configuration.issuer.absoluteString
        )
        try OIDCClaimValidation.validateAudience(
            claims.audience.value,
            expected: self.configuration.audience
        )
        try OIDCClaimValidation.validateExpiration(
            claims.expiration.value,
            clockSkew: self.configuration.clockSkew
        )
        try OIDCClaimValidation.validateNotBefore(
            claims.notBefore?.value,
            clockSkew: self.configuration.clockSkew
        )
        try OIDCClaimValidation.validateIssuedAt(
            claims.issuedAt?.value,
            clockSkew: self.configuration.clockSkew
        )

        // Build the validated token.
        return OIDCAccessToken(
            subject: OIDCSubject(
                issuer: claims.issuer.value,
                subject: claims.subject.value
            ),
            clientID: claims.clientID,
            scopes: OIDCScopeSet.parse(scope: claims.scope, scp: claims.scp),
            audience: claims.audience.value,
            expiresAt: claims.expiration.value,
            claims: OIDCClaims()
        )
    }

    // MARK: - Introspection

    private func introspect(_ token: String) async throws -> OIDCAccessToken {
        // Reuse a cached introspection result while it is valid.
        let key = Self.cacheKey(for: token)
        if let cached = self.introspectionCache[key], cached.expiresAt > Date() {
            return cached.token
        }

        // Build and send the introspection request.
        let discovery = try await self.discoveryLoader.load()
        let request = try self.introspectionRequest(discovery: discovery, token: token)
        let response = try await self.httpClient.send(request)
        guard response.statusCode == 200 else {
            throw OIDCError.introspectionFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        // Decode the introspection response.
        let introspection: OIDCIntrospectionResponse
        do {
            introspection = try JSONDecoder().decode(
                OIDCIntrospectionResponse.self,
                from: response.body
            )
        } catch {
            throw OIDCError.introspectionFailed(
                statusCode: response.statusCode,
                body: String(describing: error)
            )
        }

        // Require an active token with a subject.
        guard introspection.active else {
            throw OIDCError.inactiveAccessToken
        }
        guard let subject = introspection.sub else {
            throw OIDCError.invalidAccessToken(
                "The introspection response is missing the sub claim."
            )
        }

        // Validate the optional issuer, audience, and expiration.
        if let issuer = introspection.iss {
            try OIDCClaimValidation.validateIssuer(
                issuer,
                expected: self.configuration.issuer.absoluteString
            )
        }
        if let audience = introspection.aud {
            try OIDCClaimValidation.validateAudience(
                audience.values,
                expected: self.configuration.audience
            )
        }
        let expiresAt = introspection.exp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }
        try OIDCClaimValidation.validateExpiration(
            expiresAt,
            clockSkew: self.configuration.clockSkew
        )

        // Build the validated token.
        let accessToken = OIDCAccessToken(
            subject: OIDCSubject(
                issuer: self.configuration.issuer.absoluteString,
                subject: subject
            ),
            clientID: introspection.clientID,
            scopes: OIDCScopeSet.parse(scope: introspection.scope, scp: introspection.scp),
            audience: introspection.aud?.values ?? [],
            expiresAt: expiresAt,
            claims: OIDCClaims()
        )

        // Cache the result, bounded by the token's own expiration.
        let cacheExpiry = min(
            Date().addingTimeInterval(self.configuration.introspectionCacheDuration),
            expiresAt ?? .distantFuture
        )
        self.introspectionCache[key] = CachedIntrospection(
            token: accessToken,
            expiresAt: cacheExpiry
        )
        self.pruneIntrospectionCache()
        return accessToken
    }

    private func introspectionRequest(
        discovery: OIDCDiscovery,
        token: String
    ) throws -> OIDCHTTPRequest {
        guard let endpoint = discovery.introspectionEndpoint else {
            throw OIDCError.missingIntrospectionEndpoint
        }
        guard let clientID = self.configuration.introspectionClientID else {
            throw OIDCError.missingIntrospectionCredentials
        }

        var headers = ["Content-Type": "application/x-www-form-urlencoded"]
        var body = [
            "token": token,
            "token_type_hint": "access_token",
            "client_id": clientID,
        ]

        // Apply the configured introspection client authentication method.
        try OIDCFormRequest.applyClientAuthentication(
            headers: &headers,
            body: &body,
            clientID: clientID,
            clientSecret: self.configuration.introspectionClientSecret,
            method: self.configuration.introspectionAuthenticationMethod
        )

        return OIDCHTTPRequest(
            method: "POST",
            url: endpoint,
            headers: headers,
            body: try OIDCFormRequest.encode(body)
        )
    }

    private func pruneIntrospectionCache() {
        let now = Date()
        self.introspectionCache = self.introspectionCache.filter {
            $0.value.expiresAt > now
        }
    }

    // MARK: - Static helpers

    private static func looksLikeJWT(_ token: String) -> Bool {
        token.split(separator: ".", omittingEmptySubsequences: false).count == 3
    }

    private static func cacheKey(for token: String) -> String {
        let digest = SHA256.hash(data: Data(token.utf8))
        return Data(digest).base64URLEncodedString()
    }
}
