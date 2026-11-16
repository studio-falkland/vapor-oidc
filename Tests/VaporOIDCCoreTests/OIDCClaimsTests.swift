#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import VaporOIDCCore

@Suite("OIDCClaims")
struct OIDCClaimsTests {
    @Test
    func decodesMixedClaimValues() throws {
        let json = """
        {
          "sub": "123",
          "email_verified": true,
          "score": 1.5,
          "groups": ["a", "b"],
          "address": {"country": "NL"},
          "missing": null
        }
        """

        let claims = try JSONDecoder().decode(
            OIDCClaims.self,
            from: Data(json.utf8)
        )

        #expect(claims.string("sub") == "123")
        #expect(claims.bool("email_verified") == true)
        #expect(claims.number("score") == 1.5)
        #expect(claims.array("groups")?.count == 2)
        #expect(claims.object("address")?["country"] == .string("NL"))
        #expect(claims["missing"] == .null)
    }

    @Test
    func roundTripsAllClaimValueKinds() throws {
        let claims = OIDCClaims([
            "string": .string("value"),
            "number": .number(1.5),
            "bool": .bool(true),
            "array": .array([.string("a"), .number(2)]),
            "object": .object(["nested": .bool(false)]),
            "null": .null,
        ])

        let data = try JSONEncoder().encode(claims)
        let decoded = try JSONDecoder().decode(OIDCClaims.self, from: data)

        #expect(decoded == claims)
    }
}
