#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The OpenID Connect discovery document.
public struct OIDCDiscovery: Codable, Sendable {
    /// The issuer identifier.
    public let issuer: String

    /// The authorization endpoint.
    public let authorizationEndpoint: URL

    /// The token endpoint.
    public let tokenEndpoint: URL

    /// The UserInfo endpoint, when the provider exposes one.
    public let userinfoEndpoint: URL?

    /// The JWKS URI.
    public let jwksURI: URL

    /// The RP-initiated logout endpoint, when the provider exposes one.
    public let endSessionEndpoint: URL?

    /// The scopes the provider supports.
    public let scopesSupported: [String]?

    /// The response types the provider supports.
    public let responseTypesSupported: [String]?

    /// The PKCE challenge methods the provider supports.
    public let codeChallengeMethodsSupported: [String]?

    /// The token endpoint authentication methods the provider supports.
    public let tokenEndpointAuthMethodsSupported: [String]?

    /// The ID Token signing algorithms the provider supports.
    public let idTokenSigningAlgValuesSupported: [String]?

    /// The claims the provider supports.
    public let claimsSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case jwksURI = "jwks_uri"
        case endSessionEndpoint = "end_session_endpoint"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case claimsSupported = "claims_supported"
    }

    /// Creates a discovery document.
    public init(
        issuer: String,
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        userinfoEndpoint: URL? = nil,
        jwksURI: URL,
        endSessionEndpoint: URL? = nil,
        scopesSupported: [String]? = nil,
        responseTypesSupported: [String]? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil,
        idTokenSigningAlgValuesSupported: [String]? = nil,
        claimsSupported: [String]? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.jwksURI = jwksURI
        self.endSessionEndpoint = endSessionEndpoint
        self.scopesSupported = scopesSupported
        self.responseTypesSupported = responseTypesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.claimsSupported = claimsSupported
    }
}
