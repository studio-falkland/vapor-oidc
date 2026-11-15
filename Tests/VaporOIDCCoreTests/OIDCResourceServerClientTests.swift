#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import JWTKit
import Testing
@testable import VaporOIDCCore

@Suite("OIDCResourceServerClient")
struct OIDCResourceServerClientTests {
    private var discoveryURL: URL {
        URL(string: "https://issuer.example/.well-known/openid-configuration")!
    }

    private func configuration(
        tokenValidation: OIDCTokenValidation = .automatic,
        audience: String = "https://mcp.example.com"
    ) -> OIDCResourceServerConfiguration {
        OIDCResourceServerConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            audience: audience,
            tokenValidation: tokenValidation,
            introspectionClientID: "mcp-server",
            introspectionClientSecret: "secret"
        )
    }

    private func discovery() -> OIDCDiscovery {
        OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            userinfoEndpoint: URL(string: "https://issuer.example/userinfo")!,
            introspectionEndpoint: URL(string: "https://issuer.example/introspect")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!,
            codeChallengeMethodsSupported: ["S256"]
        )
    }

    private func claims(
        audience: [String] = ["https://mcp.example.com"],
        expiration: Date = Date().addingTimeInterval(300),
        scope: String? = "mcp:tools mcp:read",
        scp: [String]? = nil
    ) -> OIDCAccessTokenClaims {
        OIDCAccessTokenClaims(
            issuer: IssuerClaim(value: "https://issuer.example"),
            subject: SubjectClaim(value: "123"),
            audience: AudienceClaim(value: audience),
            expiration: ExpirationClaim(value: expiration),
            issuedAt: IssuedAtClaim(value: Date()),
            notBefore: nil,
            clientID: "client",
            scope: scope,
            scp: scp,
            jwtID: "jti"
        )
    }

    private func makeClient(
        claims: OIDCAccessTokenClaims,
        tokenValidation: OIDCTokenValidation = .automatic,
        audience: String = "https://mcp.example.com"
    ) async throws -> (client: OIDCResourceServerClient, token: String) {
        let privateKey = P256.Signing.PrivateKey()
        let jwk = try Self.jwk(from: privateKey, kid: "test")
        let jwks = JWKS(keys: [jwk])
        let jwksData = try JSONEncoder().encode(jwks)

        let keys = JWTKeyCollection()
        try await keys.add(jwk: jwk)
        let token = try await keys.sign(
            claims,
            kid: JWKIdentifier(string: "test")
        )

        let discovery = self.discovery()
        let discoveryData = try JSONEncoder().encode(discovery)

        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: discoveryData),
            for: self.discoveryURL
        )
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: jwksData),
            for: discovery.jwksURI
        )

        let client = OIDCResourceServerClient(
            configuration: self.configuration(
                tokenValidation: tokenValidation,
                audience: audience
            ),
            httpClient: http
        )
        return (client, token)
    }

    private func makeIntrospectionClient(
        response: OIDCIntrospectionResponse
    ) async throws -> (client: OIDCResourceServerClient, http: MockOIDCHTTPClient) {
        let discovery = self.discovery()
        let discoveryData = try JSONEncoder().encode(discovery)
        let responseData = try JSONEncoder().encode(response)

        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: discoveryData),
            for: self.discoveryURL
        )
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: responseData),
            for: discovery.introspectionEndpoint!
        )

        let client = OIDCResourceServerClient(
            configuration: self.configuration(tokenValidation: .introspection),
            httpClient: http
        )
        return (client, http)
    }

    @Test
    func validatesJWT() async throws {
        let (client, token) = try await self.makeClient(claims: self.claims())
        let accessToken = try await client.validate(token)

        #expect(accessToken.subject.issuer == "https://issuer.example")
        #expect(accessToken.subject.subject == "123")
        #expect(accessToken.clientID == "client")
        #expect(accessToken.scopes == ["mcp:tools", "mcp:read"])
        #expect(accessToken.audience == ["https://mcp.example.com"])
    }

    @Test
    func readsScopesFromSCP() async throws {
        let (client, token) = try await self.makeClient(
            claims: self.claims(scope: nil, scp: ["mcp:tools"])
        )
        let accessToken = try await client.validate(token)
        #expect(accessToken.scopes == ["mcp:tools"])
    }

    @Test
    func rejectsWrongAudience() async throws {
        let (client, token) = try await self.makeClient(
            claims: self.claims(audience: ["other"])
        )
        await #expect(throws: OIDCError.audienceMismatch) {
            _ = try await client.validate(token)
        }
    }

    @Test
    func rejectsExpiredToken() async throws {
        let (client, token) = try await self.makeClient(
            claims: self.claims(
                expiration: Date().addingTimeInterval(-3600)
            )
        )
        await #expect(throws: OIDCError.tokenExpired) {
            _ = try await client.validate(token)
        }
    }

    @Test
    func rejectsUnsupportedAlgorithm() async throws {
        let header = #"{"alg":"HS256","kid":"test"}"#
        let payload = #"{"iss":"https://issuer.example","sub":"123","aud":"https://mcp.example.com","exp":9999999999,"iat":0}"#
        let token = "\(Data(header.utf8).base64URLEncodedString()).\(Data(payload.utf8).base64URLEncodedString()).signature"

        let (client, _) = try await self.makeClient(claims: self.claims())
        await #expect(throws: OIDCError.unsupportedAlgorithm("HS256")) {
            _ = try await client.validate(token)
        }
    }

    @Test
    func introspectsOpaqueToken() async throws {
        let response = OIDCIntrospectionResponse(
            active: true,
            scope: "mcp:tools",
            scp: nil,
            clientID: "client",
            username: nil,
            tokenType: "Bearer",
            exp: Int(Date().addingTimeInterval(300).timeIntervalSince1970),
            iat: nil,
            nbf: nil,
            sub: "123",
            aud: .string("https://mcp.example.com"),
            iss: "https://issuer.example",
            jti: nil
        )
        let (client, _) = try await self.makeIntrospectionClient(response: response)
        let accessToken = try await client.validate("opaque-token")

        #expect(accessToken.subject.subject == "123")
        #expect(accessToken.scopes == ["mcp:tools"])
    }

    @Test
    func rejectsInactiveToken() async throws {
        let response = OIDCIntrospectionResponse(
            active: false,
            scope: nil,
            scp: nil,
            clientID: nil,
            username: nil,
            tokenType: nil,
            exp: nil,
            iat: nil,
            nbf: nil,
            sub: nil,
            aud: nil,
            iss: nil,
            jti: nil
        )
        let (client, _) = try await self.makeIntrospectionClient(response: response)
        await #expect(throws: OIDCError.inactiveAccessToken) {
            _ = try await client.validate("opaque-token")
        }
    }

    @Test
    func cachesIntrospection() async throws {
        let response = OIDCIntrospectionResponse(
            active: true,
            scope: "mcp:tools",
            scp: nil,
            clientID: "client",
            username: nil,
            tokenType: "Bearer",
            exp: Int(Date().addingTimeInterval(300).timeIntervalSince1970),
            iat: nil,
            nbf: nil,
            sub: "123",
            aud: .string("https://mcp.example.com"),
            iss: "https://issuer.example",
            jti: nil
        )
        let (client, http) = try await self.makeIntrospectionClient(response: response)

        _ = try await client.validate("opaque-token")
        _ = try await client.validate("opaque-token")

        let requests = await http.requests
        let introspectionRequests = requests.filter {
            $0.url == self.discovery().introspectionEndpoint
        }
        #expect(introspectionRequests.count == 1)
    }

    @Test
    func rejectsInsecureIssuer() async throws {
        let configuration = OIDCResourceServerConfiguration(
            issuer: URL(string: "http://issuer.example")!,
            audience: "https://mcp.example.com"
        )
        let client = OIDCResourceServerClient(
            configuration: configuration,
            httpClient: MockOIDCHTTPClient()
        )
        await #expect(throws: OIDCError.self) {
            _ = try await client.validate("opaque-token")
        }
    }

    private static func jwk(
        from privateKey: P256.Signing.PrivateKey,
        kid: String
    ) throws -> JWK {
        let d = privateKey.rawRepresentation
            .base64EncodedString()
            .base64URLEscaped()
        let publicKey = try ES256PublicKey(backing: privateKey.publicKey)
        guard let x = publicKey.parameters?.x.base64URLEscaped(),
              let y = publicKey.parameters?.y.base64URLEscaped() else {
            throw OIDCError.invalidAccessToken("Unable to derive the public key coordinates.")
        }
        return JWK.ecdsa(
            .es256,
            identifier: JWKIdentifier(string: kid),
            x: x,
            y: y,
            curve: .p256,
            privateKey: d
        )
    }
}

private extension String {
    func base64URLEscaped() -> String {
        self
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
