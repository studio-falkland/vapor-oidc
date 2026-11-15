#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A validated access token presented to the resource server.
public struct OIDCAccessToken: Sendable {
    /// The stable issuer and subject pair.
    public let subject: OIDCSubject

    /// The client the token was issued to, when known.
    public let clientID: String?

    /// The scopes granted to the token.
    public let scopes: Set<String>

    /// The audiences the token is intended for.
    public let audience: [String]

    /// The token expiration date, when known.
    public let expiresAt: Date?

    /// The raw claims from the token or introspection response.
    public let claims: OIDCClaims

    /// Creates an access token.
    public init(
        subject: OIDCSubject,
        clientID: String?,
        scopes: Set<String>,
        audience: [String],
        expiresAt: Date?,
        claims: OIDCClaims
    ) {
        self.subject = subject
        self.clientID = clientID
        self.scopes = scopes
        self.audience = audience
        self.expiresAt = expiresAt
        self.claims = claims
    }

    /// Returns whether the token carries a scope.
    public func hasScope(_ scope: String) -> Bool {
        self.scopes.contains(scope)
    }
}
