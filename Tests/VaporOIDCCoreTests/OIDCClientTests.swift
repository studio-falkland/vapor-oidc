#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import JWTKit
import Testing
@testable import VaporOIDCCore

@Suite("OIDCClient")
struct OIDCClientTests {
    private var discoveryURL: URL {
        URL(string: "https://issuer.example/.well-known/openid-configuration")!
    }

    private func configuration(fetchUserInfo: Bool = true) -> OIDCConfiguration {
        OIDCConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            clientID: "client",
            clientSecret: "secret",
            redirectURI: URL(string: "https://client.example/auth/callback")!,
            fetchUserInfo: fetchUserInfo
        )
    }

    private func discovery() -> OIDCDiscovery {
        OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            userinfoEndpoint: URL(string: "https://issuer.example/userinfo")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!,
            endSessionEndpoint: URL(string: "https://issuer.example/logout")!,
            codeChallengeMethodsSupported: ["S256"]
        )
    }

    private func claims(
        nonce: String? = "nonce",
        audience: [String] = ["client"],
        expiration: Date = Date().addingTimeInterval(300),
        accessTokenHash: String? = nil
    ) -> IDTokenClaims {
        IDTokenClaims(
            issuer: IssuerClaim(value: "https://issuer.example"),
            subject: SubjectClaim(value: "123"),
            audience: AudienceClaim(value: audience),
            expiration: ExpirationClaim(value: expiration),
            issuedAt: IssuedAtClaim(value: Date()),
            notBefore: nil,
            nonce: nonce,
            authorizedParty: nil,
            accessTokenHash: accessTokenHash,
            email: "user@example.com",
            emailVerified: true,
            name: "User",
            preferredUsername: nil,
            picture: nil
        )
    }

    private func makeClient(
        claims: IDTokenClaims,
        accessToken: String = "access",
        fetchUserInfo: Bool = false,
        userInfo: OIDCClaims? = nil
    ) async throws -> OIDCClient {
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
        let tokenResponse = OIDCTokenResponse(
            accessToken: accessToken,
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: nil,
            idToken: token,
            scope: "openid"
        )
        let tokenData = try JSONEncoder().encode(tokenResponse)

        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: discoveryData),
            for: self.discoveryURL
        )
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: jwksData),
            for: discovery.jwksURI
        )
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: tokenData),
            for: discovery.tokenEndpoint
        )
        if let userInfo {
            let userInfoData = try JSONEncoder().encode(userInfo)
            await http.setResponse(
                OIDCHTTPResponse(statusCode: 200, body: userInfoData),
                for: discovery.userinfoEndpoint!
            )
        }

        return OIDCClient(
            configuration: self.configuration(fetchUserInfo: fetchUserInfo),
            httpClient: http
        )
    }

    @Test
    func buildsAuthorizationURL() async throws {
        let http = MockOIDCHTTPClient()
        let discovery = self.discovery()
        let data = try JSONEncoder().encode(discovery)
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: data),
            for: self.discoveryURL
        )

        let client = OIDCClient(
            configuration: self.configuration(),
            httpClient: http
        )
        let url = try await client.authorizationURL(
            state: "state",
            nonce: "nonce",
            codeChallenge: "challenge"
        )

        let components = try #require(
            URLComponents(url: url, resolvingAgainstBaseURL: false)
        )
        let items = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).map {
                ($0.name, $0.value ?? "")
            }
        )

        #expect(items["response_type"] == "code")
        #expect(items["client_id"] == "client")
        #expect(items["redirect_uri"] == "https://client.example/auth/callback")
        #expect(items["scope"] == "openid email profile")
        #expect(items["state"] == "state")
        #expect(items["nonce"] == "nonce")
        #expect(items["code_challenge"] == "challenge")
        #expect(items["code_challenge_method"] == "S256")
    }

    @Test
    func rejectsInsecureIssuer() async throws {
        let http = MockOIDCHTTPClient()
        let configuration = OIDCConfiguration(
            issuer: URL(string: "http://issuer.example")!,
            clientID: "client",
            redirectURI: URL(string: "https://client.example/auth/callback")!
        )
        let client = OIDCClient(configuration: configuration, httpClient: http)

        await #expect(throws: OIDCError.self) {
            _ = try await client.discovery()
        }
    }

    @Test
    func validatesSignedIDToken() async throws {
        let client = try await self.makeClient(claims: self.claims())
        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )

        #expect(identity.subject.issuer == "https://issuer.example")
        #expect(identity.subject.subject == "123")
        #expect(identity.email == "user@example.com")
        #expect(identity.emailVerified == true)
    }

    @Test
    func rejectsNonceMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(nonce: "other")
        )
        await #expect(throws: OIDCError.nonceMismatch) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsAudienceMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(audience: ["other"])
        )
        await #expect(throws: OIDCError.audienceMismatch) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsUntrustedExtraAudience() async throws {
        let client = try await self.makeClient(
            claims: self.claims(audience: ["client", "other"])
        )
        await #expect(throws: OIDCError.audienceMismatch) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func refreshAcceptsIDTokenWithoutNonceRequirement() async throws {
        let client = try await self.makeClient(
            claims: self.claims(nonce: nil)
        )
        let identity = try await client.refresh(refreshToken: "refresh")
        #expect(identity.subject.subject == "123")
    }

    @Test
    func rejectsExpiredToken() async throws {
        let client = try await self.makeClient(
            claims: self.claims(
                expiration: Date().addingTimeInterval(-3600)
            )
        )
        await #expect(throws: OIDCError.tokenExpired) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsAtHashMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(accessTokenHash: "wrong")
        )
        await #expect(throws: OIDCError.self) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsUserInfoSubjectMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(),
            fetchUserInfo: true,
            userInfo: OIDCClaims(["sub": .string("other")])
        )
        await #expect(
            throws: OIDCError.userInfoSubjectMismatch(
                expected: "123",
                actual: "other"
            )
        ) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsUnsupportedAlgorithm() async throws {
        let header = #"{"alg":"HS256","kid":"test"}"#
        let payload = #"{"iss":"https://issuer.example","sub":"123","aud":"client","exp":9999999999,"iat":0}"#
        let token = "\(Data(header.utf8).base64URLEncodedString()).\(Data(payload.utf8).base64URLEncodedString()).signature"

        let discovery = self.discovery()
        let discoveryData = try JSONEncoder().encode(discovery)
        let tokenResponse = OIDCTokenResponse(
            accessToken: "access",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: nil,
            idToken: token,
            scope: "openid"
        )
        let tokenData = try JSONEncoder().encode(tokenResponse)

        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: discoveryData),
            for: self.discoveryURL
        )
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: tokenData),
            for: discovery.tokenEndpoint
        )

        let client = OIDCClient(
            configuration: self.configuration(fetchUserInfo: false),
            httpClient: http
        )
        await #expect(throws: OIDCError.unsupportedAlgorithm("HS256")) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
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
            throw OIDCError.invalidIDToken("Unable to derive the public key coordinates.")
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
