#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCFormRequest")
struct OIDCFormRequestTests {
    @Test
    func formEncodesReservedCharacters() throws {
        let body = try OIDCFormRequest.encode([
            "grant_type": "authorization_code",
            "code": "a&b=c+d% e",
        ])
        let string = String(decoding: body, as: UTF8.self)

        #expect(string.contains("grant_type=authorization_code"))
        #expect(string.contains("code=a%26b%3Dc%2Bd%25%20e"))
    }

    @Test
    func appliesBasicAuthentication() throws {
        var headers: [String: String] = [:]
        var body = ["client_id": "client"]

        try OIDCFormRequest.applyClientAuthentication(
            headers: &headers,
            body: &body,
            clientID: "client",
            clientSecret: "secret",
            method: .clientSecretBasic
        )

        #expect(headers["Authorization"] == "Basic Y2xpZW50OnNlY3JldA==")
        #expect(body["client_secret"] == nil)
    }

    @Test
    func requiresSecretForBasicAuthentication() {
        var headers: [String: String] = [:]
        var body: [String: String] = [:]

        #expect(throws: OIDCError.missingClientSecret) {
            try OIDCFormRequest.applyClientAuthentication(
                headers: &headers,
                body: &body,
                clientID: "client",
                clientSecret: nil,
                method: .clientSecretBasic
            )
        }
    }

    @Test
    func appliesPostAuthentication() throws {
        var headers: [String: String] = [:]
        var body = ["client_id": "client"]

        try OIDCFormRequest.applyClientAuthentication(
            headers: &headers,
            body: &body,
            clientID: "client",
            clientSecret: "secret",
            method: .clientSecretPost
        )

        #expect(headers["Authorization"] == nil)
        #expect(body["client_secret"] == "secret")
    }

    @Test
    func omitsAuthenticationForPublicClients() throws {
        var headers: [String: String] = [:]
        var body = ["client_id": "client"]

        try OIDCFormRequest.applyClientAuthentication(
            headers: &headers,
            body: &body,
            clientID: "client",
            clientSecret: nil,
            method: .none
        )

        #expect(headers.isEmpty)
        #expect(body["client_secret"] == nil)
    }
}
