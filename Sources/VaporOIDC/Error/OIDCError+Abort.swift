import HTTPTypes
import Vapor
import VaporOIDCCore

extension OIDCError: AbortError {
    /// Maps OIDC failures to HTTP statuses.
    public var status: HTTPResponse.Status {
        switch self {
        case .invalidState, .missingCode, .invalidRedirect:
            return .badRequest
        case .authorizationFailed, .nonceMismatch, .audienceMismatch, .tokenExpired,
             .invalidIDToken, .userInfoSubjectMismatch, .unsupportedAlgorithm,
             .invalidAccessToken, .inactiveAccessToken, .unsupportedTokenFormat:
            return .unauthorized
        case .insufficientScope:
            return .forbidden
        case .discoveryFailed, .tokenExchangeFailed, .userInfoFailed,
             .insecureEndpoint, .networkError, .missingJWKSKey, .introspectionFailed:
            return .badGateway
        case .invalidDiscoveryDocument, .issuerMismatch, .missingIDToken,
             .pkceUnsupported, .sessionUnavailable, .missingIntrospectionEndpoint,
             .missingIntrospectionCredentials:
            return .internalServerError
        }
    }

    /// Uses the localized description as the abort reason.
    public var reason: String {
        self.errorDescription ?? self.status.reasonPhrase
    }
}
