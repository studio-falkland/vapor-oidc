#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import HTTPTypes
import Testing
@testable import VaporOIDC
@testable import VaporOIDCCore

@Suite("OIDCError+Abort")
struct OIDCErrorAbortTests {
    @Test
    func mapsErrorsToStatuses() {
        let cases: [(OIDCError, HTTPResponse.Status)] = [
            (.invalidState, .badRequest),
            (.missingCode, .badRequest),
            (.invalidRedirect("/x"), .badRequest),
            (.authorizationFailed(error: "e", description: nil), .unauthorized),
            (.nonceMismatch, .unauthorized),
            (.audienceMismatch, .unauthorized),
            (.tokenExpired, .unauthorized),
            (.invalidIDToken("bad"), .unauthorized),
            (.userInfoSubjectMismatch(expected: "a", actual: "b"), .unauthorized),
            (.unsupportedAlgorithm("HS256"), .unauthorized),
            (.invalidAccessToken("bad"), .unauthorized),
            (.inactiveAccessToken, .unauthorized),
            (.unsupportedTokenFormat, .unauthorized),
            (.invalidTokenHeader("bad"), .unauthorized),
            (.invalidTokenTime("bad"), .unauthorized),
            (.insufficientScope(required: "a", granted: []), .forbidden),
            (.discoveryFailed(statusCode: 500, body: "bad"), .badGateway),
            (.tokenExchangeFailed(statusCode: 500, body: "bad"), .badGateway),
            (.userInfoFailed(statusCode: 500, body: "bad"), .badGateway),
            (.insecureEndpoint(URL(string: "http://issuer.example")!), .badGateway),
            (.networkError("down"), .badGateway),
            (.missingJWKSKey(kid: "key"), .badGateway),
            (.introspectionFailed(statusCode: 500, body: "bad"), .badGateway),
            (.invalidDiscoveryDocument("bad"), .internalServerError),
            (.issuerMismatch(expected: "a", actual: "b"), .internalServerError),
            (.missingIDToken, .internalServerError),
            (.pkceUnsupported, .internalServerError),
            (.sessionUnavailable, .internalServerError),
            (.missingIntrospectionEndpoint, .internalServerError),
            (.missingIntrospectionCredentials, .internalServerError),
            (.missingClientSecret, .internalServerError),
        ]

        for (error, status) in cases {
            #expect(error.status == status, "\(error)")
            #expect(!error.reason.isEmpty, "\(error)")
        }
    }
}
