#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit

/// The claims decoded from an ID Token.
struct IDTokenClaims: JWTPayload {
    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var issuedAt: IssuedAtClaim
    var notBefore: NotBeforeClaim?
    var nonce: String?
    var authorizedParty: String?
    var accessTokenHash: String?
    var email: String?
    var emailVerified: Bool?
    var name: String?
    var preferredUsername: String?
    var picture: String?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case nonce
        case authorizedParty = "azp"
        case accessTokenHash = "at_hash"
        case email
        case emailVerified = "email_verified"
        case name
        case preferredUsername = "preferred_username"
        case picture
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {
        // Claim checks are performed by OIDCClient so clock skew is applied
        // consistently. This method intentionally does not reject on its own.
    }
}
