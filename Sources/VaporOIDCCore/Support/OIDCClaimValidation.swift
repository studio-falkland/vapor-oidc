#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Shared claim and endpoint validation.
enum OIDCClaimValidation {
    /// Requires an endpoint to use HTTPS when enabled.
    static func requireHTTPS(_ url: URL, enabled: Bool) throws {
        guard !enabled || url.scheme == "https" else {
            throw OIDCError.insecureEndpoint(url)
        }
    }

    /// Requires the issuer to match exactly.
    static func validateIssuer(_ issuer: String, expected: String) throws {
        guard issuer == expected else {
            throw OIDCError.issuerMismatch(expected: expected, actual: issuer)
        }
    }

    /// Requires the audience to contain the expected value and no untrusted values.
    static func validateAudience(
        _ audience: [String],
        expected: String,
        trusted: Set<String> = []
    ) throws {
        guard audience.contains(expected) else {
            throw OIDCError.audienceMismatch
        }
        let trusted = trusted.union([expected])
        guard audience.allSatisfy({ trusted.contains($0) }) else {
            throw OIDCError.audienceMismatch
        }
    }

    /// Requires the expiration to be in the future, allowing clock skew.
    static func validateExpiration(_ expiration: Date?, clockSkew: TimeInterval) throws {
        guard let expiration else {
            return
        }
        guard expiration > Date().addingTimeInterval(-clockSkew) else {
            throw OIDCError.tokenExpired
        }
    }

    /// Requires the not-before time to be in the past, allowing clock skew.
    static func validateNotBefore(_ notBefore: Date?, clockSkew: TimeInterval) throws {
        guard let notBefore else {
            return
        }
        guard notBefore <= Date().addingTimeInterval(clockSkew) else {
            throw OIDCError.invalidTokenTime("The token is not valid yet.")
        }
    }

    /// Requires the issued-at time to be in the past, allowing clock skew.
    static func validateIssuedAt(_ issuedAt: Date?, clockSkew: TimeInterval) throws {
        guard let issuedAt else {
            return
        }
        guard issuedAt <= Date().addingTimeInterval(clockSkew) else {
            throw OIDCError.invalidTokenTime("The token was issued in the future.")
        }
    }
}
