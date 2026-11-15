#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit

/// The claims decoded from a JWT access token.
struct OIDCAccessTokenClaims: JWTPayload {
    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var issuedAt: IssuedAtClaim?
    var notBefore: NotBeforeClaim?
    var clientID: String?
    var scope: String?
    var scp: [String]?
    var jwtID: String?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case clientID = "client_id"
        case scope
        case scp
        case jwtID = "jti"
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {
        // Claim checks are performed by OIDCResourceServerClient so clock skew
        // is applied consistently. This method intentionally does not reject.
    }
}
