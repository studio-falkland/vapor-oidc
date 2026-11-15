#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCDiscovery")
struct OIDCDiscoveryTests {
    @Test
    func decodesSnakeCaseFields() throws {
        let json = """
        {
          "issuer": "https://issuer.example",
          "authorization_endpoint": "https://issuer.example/authorize",
          "token_endpoint": "https://issuer.example/token",
          "userinfo_endpoint": "https://issuer.example/userinfo",
          "jwks_uri": "https://issuer.example/jwks",
          "end_session_endpoint": "https://issuer.example/logout",
          "code_challenge_methods_supported": ["S256"],
          "id_token_signing_alg_values_supported": ["RS256", "ES256"]
        }
        """

        let discovery = try JSONDecoder().decode(
            OIDCDiscovery.self,
            from: Data(json.utf8)
        )

        #expect(discovery.issuer == "https://issuer.example")
        #expect(discovery.authorizationEndpoint.absoluteString == "https://issuer.example/authorize")
        #expect(discovery.tokenEndpoint.absoluteString == "https://issuer.example/token")
        #expect(discovery.userinfoEndpoint?.absoluteString == "https://issuer.example/userinfo")
        #expect(discovery.jwksURI.absoluteString == "https://issuer.example/jwks")
        #expect(discovery.endSessionEndpoint?.absoluteString == "https://issuer.example/logout")
        #expect(discovery.codeChallengeMethodsSupported == ["S256"])
    }
}
