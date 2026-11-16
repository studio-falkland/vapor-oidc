#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("MockOIDCHTTPClient")
struct MockOIDCHTTPClientTests {
    @Test
    func returnsConfiguredError() async throws {
        let http = MockOIDCHTTPClient()
        await http.setError(.networkError("down"))

        await #expect(throws: OIDCError.networkError("down")) {
            _ = try await http.send(
                OIDCHTTPRequest(
                    method: "GET",
                    url: URL(string: "https://issuer.example/jwks")!
                )
            )
        }
    }

    @Test
    func returnsNotFoundForUnknownURL() async throws {
        let http = MockOIDCHTTPClient()
        let response = try await http.send(
            OIDCHTTPRequest(
                method: "GET",
                url: URL(string: "https://issuer.example/missing")!
            )
        )

        #expect(response.statusCode == 404)
        #expect(response.body.isEmpty)
    }
}
