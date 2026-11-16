#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCJWTHeader")
struct OIDCJWTHeaderTests {
    private func token(header: String, payload: String = "{}") -> String {
        let headerPart = Data(header.utf8).base64URLEncodedString()
        let payloadPart = Data(payload.utf8).base64URLEncodedString()
        return "\(headerPart).\(payloadPart).signature"
    }

    @Test
    func decodesHeader() throws {
        let header = try OIDCJWTHeader.decode(
            self.token(header: #"{"alg":"RS256","kid":"key-1"}"#)
        )
        #expect(header.alg == "RS256")
        #expect(header.kid == "key-1")
    }

    @Test
    func rejectsMalformedToken() {
        #expect(throws: OIDCError.invalidTokenHeader("Malformed JWT.")) {
            try OIDCJWTHeader.decode("only-one-segment")
        }
    }

    @Test
    func rejectsMalformedBase64() {
        #expect(throws: OIDCError.self) {
            try OIDCJWTHeader.decode("!!!.payload.signature")
        }
    }

    @Test
    func rejectsNoneAlgorithm() throws {
        let header = try OIDCJWTHeader.decode(
            self.token(header: #"{"alg":"none"}"#)
        )
        #expect(throws: OIDCError.unsupportedAlgorithm("none")) {
            try header.validate(allowedAlgorithms: ["none"])
        }
    }

    @Test
    func rejectsHMACAlgorithms() throws {
        let header = try OIDCJWTHeader.decode(
            self.token(header: #"{"alg":"HS256"}"#)
        )
        #expect(throws: OIDCError.unsupportedAlgorithm("HS256")) {
            try header.validate(allowedAlgorithms: ["HS256"])
        }
    }

    @Test
    func rejectsAlgorithmsOutsideTheAllowlist() throws {
        let header = try OIDCJWTHeader.decode(
            self.token(header: #"{"alg":"RS256"}"#)
        )
        #expect(throws: OIDCError.unsupportedAlgorithm("RS256")) {
            try header.validate(allowedAlgorithms: ["ES256"])
        }
    }

    @Test
    func rejectsKeyReferenceHeaderParameters() throws {
        let headers = [
            #"{"alg":"RS256","x5u":"https://evil.example/cert"}"#,
            #"{"alg":"RS256","x5c":["cert"]}"#,
            #"{"alg":"RS256","jku":"https://evil.example/jwks"}"#,
            #"{"alg":"RS256","jwk":{"kty":"RSA"}}"#,
        ]

        for headerJSON in headers {
            let header = try OIDCJWTHeader.decode(self.token(header: headerJSON))
            #expect(throws: OIDCError.self) {
                try header.validate(allowedAlgorithms: ["RS256"])
            }
        }
    }

    @Test
    func acceptsSafeHeader() throws {
        let header = try OIDCJWTHeader.decode(
            self.token(header: #"{"alg":"RS256","kid":"key-1"}"#)
        )
        try header.validate(allowedAlgorithms: ["RS256"])
    }
}
