#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Errors thrown by the OIDC client.
public enum OIDCError: Error, Sendable, Equatable {
    /// The discovery request failed.
    case discoveryFailed(statusCode: Int, body: String)

    /// The discovery document could not be decoded or was incomplete.
    case invalidDiscoveryDocument(String)

    /// A provider endpoint does not use HTTPS.
    case insecureEndpoint(URL)

    /// The issuer in the discovery document or ID Token does not match.
    case issuerMismatch(expected: String, actual: String)

    /// The provider returned an authorization error.
    case authorizationFailed(error: String, description: String?)

    /// The state is missing, expired, or does not match.
    case invalidState

    /// The callback is missing the authorization code.
    case missingCode

    /// The token exchange failed.
    case tokenExchangeFailed(statusCode: Int, body: String)

    /// The token response is missing an ID Token.
    case missingIDToken

    /// The ID Token is invalid.
    case invalidIDToken(String)

    /// The nonce does not match.
    case nonceMismatch

    /// The audience does not match.
    case audienceMismatch

    /// The ID Token has expired.
    case tokenExpired

    /// The UserInfo request failed.
    case userInfoFailed(statusCode: Int, body: String)

    /// The UserInfo subject does not match the ID Token subject.
    case userInfoSubjectMismatch(expected: String, actual: String)

    /// The provider does not support PKCE `S256`.
    case pkceUnsupported

    /// The ID Token uses an unsupported algorithm.
    case unsupportedAlgorithm(String)

    /// The JWKS does not contain the key referenced by the ID Token.
    case missingJWKSKey(kid: String)

    /// A network request failed.
    case networkError(String)

    /// The session middleware is not installed.
    case sessionUnavailable

    /// The redirect target is not allowed.
    case invalidRedirect(String)

    /// The access token is invalid.
    case invalidAccessToken(String)

    /// The introspection endpoint reported the token as inactive.
    case inactiveAccessToken

    /// The introspection request failed.
    case introspectionFailed(statusCode: Int, body: String)

    /// The provider does not expose an introspection endpoint.
    case missingIntrospectionEndpoint

    /// The introspection client credentials are missing.
    case missingIntrospectionCredentials

    /// The access token is missing a required scope.
    case insufficientScope(required: String, granted: Set<String>)

    /// The access token format is not supported.
    case unsupportedTokenFormat
}

extension OIDCError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .discoveryFailed(let statusCode, let body):
            return "OIDC discovery failed (\(statusCode)): \(body)"
        case .invalidDiscoveryDocument(let reason):
            return "Invalid OIDC discovery document: \(reason)"
        case .insecureEndpoint(let url):
            return "OIDC endpoint must use HTTPS: \(url)"
        case .issuerMismatch(let expected, let actual):
            return "OIDC issuer mismatch: expected \(expected), got \(actual)"
        case .authorizationFailed(let error, let description):
            return "OIDC authorization failed: \(error)\(description.map { ": \($0)" } ?? "")"
        case .invalidState:
            return "Invalid or expired OIDC state."
        case .missingCode:
            return "The OIDC callback is missing the authorization code."
        case .tokenExchangeFailed(let statusCode, let body):
            return "OIDC token exchange failed (\(statusCode)): \(body)"
        case .missingIDToken:
            return "The OIDC token response is missing an ID token."
        case .invalidIDToken(let reason):
            return "Invalid OIDC ID token: \(reason)"
        case .nonceMismatch:
            return "The OIDC nonce does not match."
        case .audienceMismatch:
            return "The OIDC ID token audience does not match."
        case .tokenExpired:
            return "The OIDC ID token has expired."
        case .userInfoFailed(let statusCode, let body):
            return "OIDC UserInfo request failed (\(statusCode)): \(body)"
        case .userInfoSubjectMismatch(let expected, let actual):
            return "OIDC UserInfo subject mismatch: expected \(expected), got \(actual)"
        case .pkceUnsupported:
            return "The OIDC provider does not support PKCE S256."
        case .unsupportedAlgorithm(let algorithm):
            return "Unsupported OIDC ID token algorithm: \(algorithm)"
        case .missingJWKSKey(let kid):
            return "The OIDC JWKS does not contain the key \(kid)."
        case .networkError(let reason):
            return "OIDC network error: \(reason)"
        case .sessionUnavailable:
            return "OIDC requires SessionsMiddleware."
        case .invalidRedirect(let value):
            return "Invalid OIDC redirect target: \(value)"
        case .invalidAccessToken(let reason):
            return "Invalid OIDC access token: \(reason)"
        case .inactiveAccessToken:
            return "The OIDC access token is inactive."
        case .introspectionFailed(let statusCode, let body):
            return "OIDC introspection failed (\(statusCode)): \(body)"
        case .missingIntrospectionEndpoint:
            return "The OIDC provider does not expose an introspection endpoint."
        case .missingIntrospectionCredentials:
            return "The OIDC introspection client credentials are missing."
        case .insufficientScope(let required, let granted):
            return "The OIDC access token is missing the \(required) scope. Granted: \(granted.sorted().joined(separator: " "))"
        case .unsupportedTokenFormat:
            return "The OIDC access token format is not supported."
        }
    }
}
