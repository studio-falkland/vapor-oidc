#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The tokens returned by the provider.
public struct OIDCTokens: Sendable {
    /// The access token.
    public let accessToken: String

    /// The refresh token, when the provider issued one.
    public let refreshToken: String?

    /// The ID token, when the provider returned one.
    public let idToken: String?

    /// The token type.
    public let tokenType: String

    /// The access token expiration date, when known.
    public let expiresAt: Date?

    /// The granted scope, when the provider returned one.
    public let scope: String?

    /// Creates a token set.
    public init(
        accessToken: String,
        refreshToken: String?,
        idToken: String?,
        tokenType: String,
        expiresAt: Date?,
        scope: String?
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.scope = scope
    }
}
