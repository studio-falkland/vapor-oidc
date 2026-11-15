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
    private let logger: Logger

    private var cachedDiscovery: OIDCDiscovery?
    private var cachedJWKS: JWKS?
    private var jwksFetchedAt: Date?
    private var keys = JWTKeyCollection()
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
        self.logger = logger
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

    // MARK: - Discovery

    private func discovery() async throws -> OIDCDiscovery {
        // Reuse the cached document.
        if let cachedDiscovery {
            return cachedDiscovery
        }

        // Build the discovery URL and require HTTPS.
        let url = self.configuration.discoveryURL
            ?? self.configuration.issuer.appendingPathComponent(".well-known/openid-configuration")
        try self.validateHTTPS(url)

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
        guard discovery.issuer == self.configuration.issuer.absoluteString else {
            throw OIDCError.issuerMismatch(
                expected: self.configuration.issuer.absoluteString,
                actual: discovery.issuer
            )
        }

        // Require the endpoints we use to use HTTPS.
        try self.validateHTTPS(discovery.jwksURI)
        if let introspectionEndpoint = discovery.introspectionEndpoint {
            try self.validateHTTPS(introspectionEndpoint)
        }

        self.cachedDiscovery = discovery
        return discovery
    }

    // MARK: - JWT validation

    private func validateJWT(_ token: String) async throws -> OIDCAccessToken {
        // Decode the header and reject unsafe algorithms and key references.
        let header = try Self.decodeHeader(token)
        let algorithm = header.alg.lowercased()

        guard algorithm != "none", !algorithm.hasPrefix("hs") else {
            throw OIDCError.unsupportedAlgorithm(header.alg)
        }
        guard self.configuration.allowedAccessTokenAlgorithms.contains(header.alg) else {
            throw OIDCError.unsupportedAlgorithm(header.alg)
        }
        guard header.x5u == nil, header.x5c == nil, header.jku == nil, header.jwk == nil else {
            throw OIDCError.invalidAccessToken("Unsupported JOSE header parameters.")
        }

        // Load the JWKS and require a kid when the set has multiple keys.
        try await self.loadJWKSIfNeeded()
        if header.kid == nil, let jwks = self.cachedJWKS, jwks.keys.count > 1 {
            throw OIDCError.missingJWKSKey(kid: "<missing>")
        }

        // Verify the signature, refreshing the JWKS once on failure.
        let claims: OIDCAccessTokenClaims
        do {
            claims = try await self.keys.verify(token, as: OIDCAccessTokenClaims.self)
        } catch {
            try await self.refreshJWKS()
            do {
                claims = try await self.keys.verify(token, as: OIDCAccessTokenClaims.self)
            } catch {
                throw OIDCError.invalidAccessToken(String(describing: error))
            }
        }

        // Validate the issuer, audience, and time-based claims.
        try self.validateIssuer(claims.issuer.value)
        try self.validateAudience(claims.audience.value)
        try self.validateExpiration(claims.expiration.value)
        try self.validateNotBefore(claims.notBefore?.value)
        try self.validateIssuedAt(claims.issuedAt?.value)

        // Build the validated token.
        return OIDCAccessToken(
            subject: OIDCSubject(
                issuer: claims.issuer.value,
                subject: claims.subject.value
            ),
            clientID: claims.clientID,
            scopes: Self.scopeSet(scope: claims.scope, scp: claims.scp),
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
        let discovery = try await self.discovery()
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
            try self.validateIssuer(issuer)
        }
        if let audience = introspection.aud {
            try self.validateAudience(audience.values)
        }
        let expiresAt = introspection.exp.map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }
        try self.validateExpiration(expiresAt)

        // Build the validated token.
        let accessToken = OIDCAccessToken(
            subject: OIDCSubject(
                issuer: self.configuration.issuer.absoluteString,
                subject: subject
            ),
            clientID: introspection.clientID,
            scopes: Self.scopeSet(scope: introspection.scope, scp: introspection.scp),
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
        switch self.configuration.introspectionAuthenticationMethod {
        case .clientSecretBasic:
            guard let secret = self.configuration.introspectionClientSecret else {
                throw OIDCError.missingIntrospectionCredentials
            }
            let credentials = "\(clientID):\(secret)"
            headers["Authorization"] = "Basic \(Data(credentials.utf8).base64EncodedString())"
        case .clientSecretPost:
            if let secret = self.configuration.introspectionClientSecret {
                body["client_secret"] = secret
            }
        case .none:
            break
        }

        // Form-encode the body.
        let encodedBody = body
            .map { "\(Self.formEncode($0.key))=\(Self.formEncode($0.value))" }
            .joined(separator: "&")

        return OIDCHTTPRequest(
            method: "POST",
            url: endpoint,
            headers: headers,
            body: Data(encodedBody.utf8)
        )
    }

    private func pruneIntrospectionCache() {
        let now = Date()
        self.introspectionCache = self.introspectionCache.filter {
            $0.value.expiresAt > now
        }
    }

    // MARK: - JWKS

    private func loadJWKSIfNeeded() async throws {
        // Reuse the cached JWKS until it expires.
        if let jwksFetchedAt,
           Date().timeIntervalSince(jwksFetchedAt) < self.configuration.jwksCacheDuration {
            return
        }
        try await self.refreshJWKS()
    }

    private func refreshJWKS() async throws {
        // Fetch the JWKS from the provider.
        let discovery = try await self.discovery()
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
        self.jwksFetchedAt = Date()
    }

    // MARK: - Validation helpers

    private func validateIssuer(_ issuer: String) throws {
        guard issuer == self.configuration.issuer.absoluteString else {
            throw OIDCError.issuerMismatch(
                expected: self.configuration.issuer.absoluteString,
                actual: issuer
            )
        }
    }

    private func validateAudience(_ audience: [String]) throws {
        guard audience.contains(self.configuration.audience) else {
            throw OIDCError.audienceMismatch
        }
    }

    private func validateExpiration(_ expiration: Date?) throws {
        guard let expiration else {
            return
        }
        guard expiration > Date().addingTimeInterval(-self.configuration.clockSkew) else {
            throw OIDCError.tokenExpired
        }
    }

    private func validateNotBefore(_ notBefore: Date?) throws {
        guard let notBefore else {
            return
        }
        guard notBefore <= Date().addingTimeInterval(self.configuration.clockSkew) else {
            throw OIDCError.invalidAccessToken("The access token is not valid yet.")
        }
    }

    private func validateIssuedAt(_ issuedAt: Date?) throws {
        guard let issuedAt else {
            return
        }
        guard issuedAt <= Date().addingTimeInterval(self.configuration.clockSkew) else {
            throw OIDCError.invalidAccessToken("The access token was issued in the future.")
        }
    }

    private func validateHTTPS(_ url: URL) throws {
        guard !self.configuration.requireHTTPS || url.scheme == "https" else {
            throw OIDCError.insecureEndpoint(url)
        }
    }

    // MARK: - Static helpers

    private static func looksLikeJWT(_ token: String) -> Bool {
        token.split(separator: ".", omittingEmptySubsequences: false).count == 3
    }

    private static func scopeSet(scope: String?, scp: [String]?) -> Set<String> {
        var scopes = Set<String>()
        if let scope {
            scopes.formUnion(scope.split(separator: " ").map(String.init))
        }
        if let scp {
            scopes.formUnion(scp)
        }
        return scopes
    }

    private static func cacheKey(for token: String) -> String {
        let digest = SHA256.hash(data: Data(token.utf8))
        return Data(digest).base64URLEncodedString()
    }

    private static func formEncode(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    private static func decodeHeader(_ token: String) throws -> AccessTokenHeader {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw OIDCError.invalidAccessToken("Malformed JWT.")
        }
        guard let data = Data(base64URLEncoded: String(parts[0])) else {
            throw OIDCError.invalidAccessToken("Malformed JWT header.")
        }
        do {
            return try JSONDecoder().decode(AccessTokenHeader.self, from: data)
        } catch {
            throw OIDCError.invalidAccessToken("Unable to decode the JWT header: \(error)")
        }
    }
}

private struct AccessTokenHeader: Decodable {
    let alg: String
    let kid: String?
    let x5u: String?
    let x5c: [String]?
    let jku: String?
    let jwk: OIDCClaimValue?
}
