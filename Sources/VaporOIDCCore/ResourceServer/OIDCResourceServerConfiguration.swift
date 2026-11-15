#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The configuration for an OAuth 2.1 resource server.
public struct OIDCResourceServerConfiguration: Sendable {
    /// The issuer identifier of the authorization server.
    public var issuer: URL

    /// The resource identifier this server expects in the `aud` claim.
    public var audience: String

    /// The scopes every request must carry.
    public var requiredScopes: Set<String>

    /// How access tokens are validated.
    public var tokenValidation: OIDCTokenValidation

    /// The client ID used for token introspection.
    public var introspectionClientID: String?

    /// The client secret used for token introspection.
    public var introspectionClientSecret: String?

    /// The client authentication method used for introspection.
    public var introspectionAuthenticationMethod: OIDCTokenEndpointAuthenticationMethod

    /// The clock skew applied to time-based claims.
    public var clockSkew: TimeInterval

    /// How long the JWKS is cached before it is refreshed.
    public var jwksCacheDuration: TimeInterval

    /// How long an introspection result is cached.
    public var introspectionCacheDuration: TimeInterval

    /// The access-token signing algorithms accepted from the provider.
    public var allowedAccessTokenAlgorithms: Set<String>

    /// Whether provider endpoints must use HTTPS.
    public var requireHTTPS: Bool

    /// An optional discovery URL override.
    public var discoveryURL: URL?

    /// The URL of the protected resource metadata document.
    public var protectedResourceMetadataURL: URL?

    /// Creates a resource-server configuration.
    public init(
        issuer: URL,
        audience: String,
        requiredScopes: Set<String> = [],
        tokenValidation: OIDCTokenValidation = .automatic,
        introspectionClientID: String? = nil,
        introspectionClientSecret: String? = nil,
        introspectionAuthenticationMethod: OIDCTokenEndpointAuthenticationMethod? = nil,
        clockSkew: TimeInterval = 60,
        jwksCacheDuration: TimeInterval = 3600,
        introspectionCacheDuration: TimeInterval = 30,
        allowedAccessTokenAlgorithms: Set<String> = ["RS256", "ES256"],
        requireHTTPS: Bool = true,
        discoveryURL: URL? = nil,
        protectedResourceMetadataURL: URL? = nil
    ) {
        self.issuer = issuer
        self.audience = audience
        self.requiredScopes = requiredScopes
        self.tokenValidation = tokenValidation
        self.introspectionClientID = introspectionClientID
        self.introspectionClientSecret = introspectionClientSecret
        self.introspectionAuthenticationMethod = introspectionAuthenticationMethod
            ?? (introspectionClientSecret == nil ? .none : .clientSecretBasic)
        self.clockSkew = clockSkew
        self.jwksCacheDuration = jwksCacheDuration
        self.introspectionCacheDuration = introspectionCacheDuration
        self.allowedAccessTokenAlgorithms = allowedAccessTokenAlgorithms
        self.requireHTTPS = requireHTTPS
        self.discoveryURL = discoveryURL
        self.protectedResourceMetadataURL = protectedResourceMetadataURL
            ?? URL(string: audience)?.appendingPathComponent(".well-known/oauth-protected-resource")
    }
}
