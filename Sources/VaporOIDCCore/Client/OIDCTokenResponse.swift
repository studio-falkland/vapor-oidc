#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The token endpoint response.
public struct OIDCTokenResponse: Codable, Sendable {
    /// The access token.
    public let accessToken: String

    /// The token type.
    public let tokenType: String

    /// The access token lifetime in seconds.
    public let expiresIn: Int?

    /// The refresh token, when issued.
    public let refreshToken: String?

    /// The ID token, when issued.
    public let idToken: String?

    /// The granted scope, when returned.
    public let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case scope
    }
}
