#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The identity returned by a successful login.
public struct OIDCIdentity: Sendable {
    /// The stable issuer and subject pair.
    public let subject: OIDCSubject

    /// The user's email address, when provided.
    public let email: String?

    /// Whether the provider verified the email address.
    public let emailVerified: Bool?

    /// The user's display name, when provided.
    public let name: String?

    /// The user's preferred username, when provided.
    public let preferredUsername: String?

    /// The user's profile picture, when provided.
    public let picture: URL?

    /// The merged ID Token and UserInfo claims.
    public let claims: OIDCClaims

    /// The tokens returned by the provider.
    public let tokens: OIDCTokens

    /// Creates an identity.
    public init(
        subject: OIDCSubject,
        email: String?,
        emailVerified: Bool?,
        name: String?,
        preferredUsername: String?,
        picture: URL?,
        claims: OIDCClaims,
        tokens: OIDCTokens
    ) {
        self.subject = subject
        self.email = email
        self.emailVerified = emailVerified
        self.name = name
        self.preferredUsername = preferredUsername
        self.picture = picture
        self.claims = claims
        self.tokens = tokens
    }
}
