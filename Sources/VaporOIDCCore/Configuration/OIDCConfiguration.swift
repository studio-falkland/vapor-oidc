#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The client configuration for an OpenID Connect provider.
public struct OIDCConfiguration: Sendable {
    /// The issuer identifier of the provider.
    public var issuer: URL

    /// The OAuth 2.0 client identifier.
    public var clientID: String

    /// The client secret for confidential clients.
    public var clientSecret: String?

    /// The exact redirect URI registered with the provider.
    public var redirectURI: URL

    /// The scopes requested at the authorization endpoint.
    public var scopes: [String]

    /// Whether to use PKCE `S256`.
    public var usePKCE: Bool

    /// Whether to send and validate a nonce.
    public var useNonce: Bool

    /// Whether to fetch the UserInfo endpoint after login.
    public var fetchUserInfo: Bool

    /// An optional discovery URL override.
    public var discoveryURL: URL?

    /// The token endpoint authentication method.
    public var tokenEndpointAuthenticationMethod: OIDCTokenEndpointAuthenticationMethod

    /// Extra parameters appended to the authorization request.
    public var additionalAuthorizationParameters: [String: String]

    /// The clock skew applied to time-based claims.
    public var clockSkew: TimeInterval

    /// How long the JWKS is cached before it is refreshed.
    public var jwksCacheDuration: TimeInterval

    /// What to do when the UserInfo request fails.
    public var userInfoFailurePolicy: OIDCUserInfoFailurePolicy

    /// Additional audiences trusted in the ID Token.
    ///
    /// The client ID is always trusted. Any other audience must be listed here,
    /// otherwise the ID Token is rejected.
    public var trustedAudiences: Set<String>

    /// The ID Token signing algorithms accepted from the provider.
    public var allowedIDTokenAlgorithms: Set<String>

    /// Whether provider endpoints must use HTTPS.
    public var requireHTTPS: Bool

    /// Creates a configuration.
    public init(
        issuer: URL,
        clientID: String,
        clientSecret: String? = nil,
        redirectURI: URL,
        scopes: [String] = ["openid", "email", "profile"],
        usePKCE: Bool = true,
        useNonce: Bool = true,
        fetchUserInfo: Bool = true,
        discoveryURL: URL? = nil,
        tokenEndpointAuthenticationMethod: OIDCTokenEndpointAuthenticationMethod? = nil,
        additionalAuthorizationParameters: [String: String] = [:],
        clockSkew: TimeInterval = 60,
        jwksCacheDuration: TimeInterval = 3600,
        userInfoFailurePolicy: OIDCUserInfoFailurePolicy = .fail,
        trustedAudiences: Set<String> = [],
        allowedIDTokenAlgorithms: Set<String> = ["RS256", "ES256"],
        requireHTTPS: Bool = true
    ) {
        self.issuer = issuer
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.usePKCE = usePKCE
        self.useNonce = useNonce
        self.fetchUserInfo = fetchUserInfo
        self.discoveryURL = discoveryURL
        self.tokenEndpointAuthenticationMethod = tokenEndpointAuthenticationMethod
            ?? (clientSecret == nil ? .none : .clientSecretBasic)
        self.additionalAuthorizationParameters = additionalAuthorizationParameters
        self.clockSkew = clockSkew
        self.jwksCacheDuration = jwksCacheDuration
        self.userInfoFailurePolicy = userInfoFailurePolicy
        self.trustedAudiences = trustedAudiences
        self.allowedIDTokenAlgorithms = allowedIDTokenAlgorithms
        self.requireHTTPS = requireHTTPS
    }
}

/// The client authentication method used at the token endpoint.
public enum OIDCTokenEndpointAuthenticationMethod: String, Codable, Sendable {
    /// HTTP Basic authentication with the client ID and secret.
    case clientSecretBasic = "client_secret_basic"

    /// The client ID and secret are sent in the request body.
    case clientSecretPost = "client_secret_post"

    /// No client authentication (public client).
    case none
}

/// What to do when the UserInfo request fails.
public enum OIDCUserInfoFailurePolicy: Sendable {
    /// Fail the login.
    case fail

    /// Log the failure and continue with the ID Token claims.
    case ignore
}
