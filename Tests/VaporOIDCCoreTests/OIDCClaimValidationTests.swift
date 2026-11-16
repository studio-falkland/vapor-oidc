#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCClaimValidation")
struct OIDCClaimValidationTests {
    @Test
    func requiresHTTPSOnlyWhenEnabled() throws {
        let insecure = URL(string: "http://issuer.example")!
        let secure = URL(string: "https://issuer.example")!

        #expect(throws: OIDCError.insecureEndpoint(insecure)) {
            try OIDCClaimValidation.requireHTTPS(insecure, enabled: true)
        }
        try OIDCClaimValidation.requireHTTPS(insecure, enabled: false)
        try OIDCClaimValidation.requireHTTPS(secure, enabled: true)
    }

    @Test
    func requiresExactIssuerMatch() throws {
        try OIDCClaimValidation.validateIssuer(
            "https://issuer.example",
            expected: "https://issuer.example"
        )
        #expect(
            throws: OIDCError.issuerMismatch(
                expected: "https://issuer.example",
                actual: "https://issuer.example/"
            )
        ) {
            try OIDCClaimValidation.validateIssuer(
                "https://issuer.example/",
                expected: "https://issuer.example"
            )
        }
    }

    @Test
    func validatesAudience() throws {
        try OIDCClaimValidation.validateAudience(["client"], expected: "client")
        try OIDCClaimValidation.validateAudience(
            ["client", "other"],
            expected: "client",
            trusted: ["other"]
        )

        #expect(throws: OIDCError.audienceMismatch) {
            try OIDCClaimValidation.validateAudience(["other"], expected: "client")
        }
        #expect(throws: OIDCError.audienceMismatch) {
            try OIDCClaimValidation.validateAudience(
                ["client", "other"],
                expected: "client"
            )
        }
    }

    @Test
    func validatesExpirationWithClockSkew() throws {
        try OIDCClaimValidation.validateExpiration(
            Date().addingTimeInterval(60),
            clockSkew: 0
        )
        try OIDCClaimValidation.validateExpiration(
            Date().addingTimeInterval(-30),
            clockSkew: 60
        )
        try OIDCClaimValidation.validateExpiration(nil, clockSkew: 0)

        #expect(throws: OIDCError.tokenExpired) {
            try OIDCClaimValidation.validateExpiration(
                Date().addingTimeInterval(-120),
                clockSkew: 60
            )
        }
    }

    @Test
    func validatesNotBeforeWithClockSkew() throws {
        try OIDCClaimValidation.validateNotBefore(
            Date().addingTimeInterval(-60),
            clockSkew: 0
        )
        try OIDCClaimValidation.validateNotBefore(
            Date().addingTimeInterval(30),
            clockSkew: 60
        )
        try OIDCClaimValidation.validateNotBefore(nil, clockSkew: 0)

        #expect(
            throws: OIDCError.invalidTokenTime("The token is not valid yet.")
        ) {
            try OIDCClaimValidation.validateNotBefore(
                Date().addingTimeInterval(120),
                clockSkew: 60
            )
        }
    }

    @Test
    func validatesIssuedAtWithClockSkew() throws {
        try OIDCClaimValidation.validateIssuedAt(
            Date().addingTimeInterval(-60),
            clockSkew: 0
        )
        try OIDCClaimValidation.validateIssuedAt(
            Date().addingTimeInterval(30),
            clockSkew: 60
        )
        try OIDCClaimValidation.validateIssuedAt(nil, clockSkew: 0)

        #expect(
            throws: OIDCError.invalidTokenTime("The token was issued in the future.")
        ) {
            try OIDCClaimValidation.validateIssuedAt(
                Date().addingTimeInterval(120),
                clockSkew: 60
            )
        }
    }
}
