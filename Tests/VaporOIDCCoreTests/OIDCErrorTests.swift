#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCError")
struct OIDCErrorTests {
    @Test
    func providesLocalizedDescriptions() {
        let cases: [(OIDCError, String)] = [
            (.discoveryFailed(statusCode: 500, body: "boom"), "OIDC discovery failed (500)"),
            (.invalidDiscoveryDocument("bad"), "Invalid OIDC discovery document: bad"),
            (.insecureEndpoint(URL(string: "http://issuer.example")!), "must use HTTPS"),
            (.issuerMismatch(expected: "a", actual: "b"), "issuer mismatch"),
            (.authorizationFailed(error: "access_denied", description: "nope"), "access_denied: nope"),
            (.invalidState, "Invalid or expired OIDC state"),
            (.missingCode, "missing the authorization code"),
            (.tokenExchangeFailed(statusCode: 400, body: "bad"), "OIDC token exchange failed (400)"),
            (.missingIDToken, "missing an ID token"),
            (.invalidIDToken("bad"), "Invalid OIDC ID token: bad"),
            (.nonceMismatch, "nonce does not match"),
            (.audienceMismatch, "audience does not match"),
            (.tokenExpired, "has expired"),
            (.userInfoFailed(statusCode: 500, body: "bad"), "OIDC UserInfo request failed (500)"),
            (.userInfoSubjectMismatch(expected: "a", actual: "b"), "subject mismatch"),
            (.pkceUnsupported, "does not support PKCE S256"),
            (.unsupportedAlgorithm("HS256"), "Unsupported OIDC ID token algorithm: HS256"),
            (.missingJWKSKey(kid: "key"), "does not contain the key key"),
            (.networkError("down"), "OIDC network error: down"),
            (.sessionUnavailable, "requires SessionsMiddleware"),
            (.invalidRedirect("/x"), "Invalid OIDC redirect target: /x"),
            (.invalidAccessToken("bad"), "Invalid OIDC access token: bad"),
            (.inactiveAccessToken, "is inactive"),
            (.introspectionFailed(statusCode: 500, body: "bad"), "OIDC introspection failed (500)"),
            (.missingIntrospectionEndpoint, "does not expose an introspection endpoint"),
            (.missingIntrospectionCredentials, "introspection client credentials are missing"),
            (.insufficientScope(required: "a", granted: ["b"]), "missing the a scope"),
            (.unsupportedTokenFormat, "format is not supported"),
            (.invalidTokenHeader("bad"), "Invalid OIDC token header: bad"),
            (.invalidTokenTime("bad"), "Invalid OIDC token time: bad"),
            (.missingClientSecret, "client secret is missing"),
        ]

        for (error, expected) in cases {
            let description = error.errorDescription ?? ""
            #expect(
                description.contains(expected),
                "\(error) produced: \(description)"
            )
        }
    }
}
