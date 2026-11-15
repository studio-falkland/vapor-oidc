#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCState")
struct OIDCStateTests {
    @Test
    func generatesDistinctValues() {
        let first = OIDCState.generate(
            issuer: "https://issuer.example",
            redirectAfterLogin: "/a"
        )
        let second = OIDCState.generate(
            issuer: "https://issuer.example",
            redirectAfterLogin: "/b"
        )

        #expect(first.state != second.state)
        #expect(first.nonce != second.nonce)
        #expect(first.codeVerifier != second.codeVerifier)
        #expect(first.issuer == "https://issuer.example")
        #expect(first.redirectAfterLogin == "/a")
    }

    @Test
    func codeChallengeMatchesVerifier() throws {
        let state = OIDCState.generate(
            issuer: "https://issuer.example",
            redirectAfterLogin: nil
        )
        let verifier = try #require(state.codeVerifier)
        #expect(state.codeChallenge == OIDCPKCE.challenge(for: verifier))
    }

    @Test
    func roundTripsThroughJSON() throws {
        let state = OIDCState.generate(
            issuer: "https://issuer.example",
            redirectAfterLogin: "/dashboard"
        )
        let data = try JSONEncoder().encode(state)
        let decoded = try JSONDecoder().decode(OIDCState.self, from: data)

        #expect(decoded.state == state.state)
        #expect(decoded.nonce == state.nonce)
        #expect(decoded.codeVerifier == state.codeVerifier)
        #expect(decoded.issuer == state.issuer)
        #expect(decoded.redirectAfterLogin == state.redirectAfterLogin)
    }
}
