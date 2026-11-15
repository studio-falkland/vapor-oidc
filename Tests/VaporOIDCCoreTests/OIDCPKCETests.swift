import Testing
@testable import VaporOIDCCore

@Suite("OIDCPKCE")
struct OIDCPKCETests {
    @Test
    func challengeMatchesRFC7636Example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = OIDCPKCE.challenge(for: verifier)
        #expect(challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test
    func generatedVerifierHasValidLength() {
        let pkce = OIDCPKCE.generate()
        #expect(pkce.verifier.count >= 43)
        #expect(pkce.verifier.count <= 128)
        #expect(pkce.challenge == OIDCPKCE.challenge(for: pkce.verifier))
    }
}
