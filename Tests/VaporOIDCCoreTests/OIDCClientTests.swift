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

    private func configuration(
        fetchUserInfo: Bool = true,
        useNonce: Bool = true,
        userInfoFailurePolicy: OIDCUserInfoFailurePolicy = .fail,
        trustedAudiences: Set<String> = [],
        allowedIDTokenAlgorithms: Set<String> = ["RS256", "ES256"]
    ) -> OIDCConfiguration {
        OIDCConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            clientID: "client",
            clientSecret: "secret",
            redirectURI: URL(string: "https://client.example/auth/callback")!,
            useNonce: useNonce,
            fetchUserInfo: fetchUserInfo,
            userInfoFailurePolicy: userInfoFailurePolicy,
            trustedAudiences: trustedAudiences,
            allowedIDTokenAlgorithms: allowedIDTokenAlgorithms
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
        issuer: String = "https://issuer.example",
        subject: String = "123",
        nonce: String? = "nonce",
        audience: [String] = ["client"],
        expiration: Date = Date().addingTimeInterval(300),
        issuedAt: Date = Date(),
        notBefore: Date? = nil,
        authorizedParty: String? = nil,
        accessTokenHash: String? = nil,
        email: String? = "user@example.com",
        emailVerified: Bool? = true,
        name: String? = "User"
    ) -> IDTokenClaims {
        IDTokenClaims(
            issuer: IssuerClaim(value: issuer),
            subject: SubjectClaim(value: subject),
            audience: AudienceClaim(value: audience),
            expiration: ExpirationClaim(value: expiration),
            issuedAt: IssuedAtClaim(value: issuedAt),
            notBefore: notBefore.map { NotBeforeClaim(value: $0) },
            nonce: nonce,
            authorizedParty: authorizedParty,
            accessTokenHash: accessTokenHash,
            email: email,
            emailVerified: emailVerified,
            name: name,
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
        let signed = try await self.signedToken(claims: claims)
        return try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: fetchUserInfo),
            token: signed.token,
            jwks: signed.jwks,
            accessToken: accessToken,
            userInfo: userInfo
        )
    }

    private func makeClient(
        configuration: OIDCConfiguration,
        token: String?,
        jwks: JWKS,
        accessToken: String = "access",
        refreshToken: String? = nil,
        userInfo: OIDCClaims? = nil,
        userInfoStatusCode: Int = 200
    ) async throws -> OIDCClient {
        let discovery = self.discovery()
        let discoveryData = try JSONEncoder().encode(discovery)
        let jwksData = try JSONEncoder().encode(jwks)
        let tokenResponse = OIDCTokenResponse(
            accessToken: accessToken,
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: refreshToken,
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
                OIDCHTTPResponse(statusCode: userInfoStatusCode, body: userInfoData),
                for: discovery.userinfoEndpoint!
            )
        }

        return OIDCClient(configuration: configuration, httpClient: http)
    }

    private func signedToken(
        claims: IDTokenClaims,
        kid: String? = "test"
    ) async throws -> (token: String, jwks: JWKS) {
        let privateKey = P256.Signing.PrivateKey()
        let jwk = try Self.jwk(from: privateKey, kid: kid ?? "test")
        let keys = JWTKeyCollection()
        try await keys.add(jwk: jwk)
        let token = try await keys.sign(
            claims,
            kid: kid.map { JWKIdentifier(string: $0) }
        )
        return (token, JWKS(keys: [jwk]))
    }

    private func rawToken(header: String, payload: String) -> String {
        let headerPart = Data(header.utf8).base64URLEncodedString()
        let payloadPart = Data(payload.utf8).base64URLEncodedString()
        return "\(headerPart).\(payloadPart).signature"
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
    func acceptsTrustedExtraAudience() async throws {
        let signed = try await self.signedToken(
            claims: self.claims(audience: ["client", "other"])
        )
        let client = try await self.makeClient(
            configuration: self.configuration(
                fetchUserInfo: false,
                trustedAudiences: ["other"]
            ),
            token: signed.token,
            jwks: signed.jwks
        )

        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )
        #expect(identity.subject.subject == "123")
    }

    @Test
    func rejectsIssuerMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(issuer: "https://evil.example")
        )
        await #expect(
            throws: OIDCError.issuerMismatch(
                expected: "https://issuer.example",
                actual: "https://evil.example"
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
    func rejectsAuthorizedPartyMismatch() async throws {
        let client = try await self.makeClient(
            claims: self.claims(authorizedParty: "other")
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
    func rejectsNotBeforeInFuture() async throws {
        let client = try await self.makeClient(
            claims: self.claims(notBefore: Date().addingTimeInterval(600))
        )
        await #expect(
            throws: OIDCError.invalidTokenTime("The token is not valid yet.")
        ) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsIssuedAtInFuture() async throws {
        let client = try await self.makeClient(
            claims: self.claims(issuedAt: Date().addingTimeInterval(600))
        )
        await #expect(
            throws: OIDCError.invalidTokenTime("The token was issued in the future.")
        ) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsMissingIssuedAt() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let jwk = try Self.jwk(from: privateKey, kid: "test")
        let keys = JWTKeyCollection()
        try await keys.add(jwk: jwk)
        let token = try await keys.sign(
            ClaimsWithoutIssuedAt(
                issuer: IssuerClaim(value: "https://issuer.example"),
                subject: SubjectClaim(value: "123"),
                audience: AudienceClaim(value: ["client"]),
                expiration: ExpirationClaim(value: Date().addingTimeInterval(300)),
                nonce: "nonce"
            ),
            kid: JWKIdentifier(string: "test")
        )

        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: false),
            token: token,
            jwks: JWKS(keys: [jwk])
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
    func rejectsNoneAlgorithm() async throws {
        let token = self.rawToken(
            header: #"{"alg":"none"}"#,
            payload: #"{"iss":"https://issuer.example","sub":"123","aud":"client","exp":9999999999,"iat":0}"#
        )
        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: false),
            token: token,
            jwks: JWKS(keys: [])
        )

        await #expect(throws: OIDCError.unsupportedAlgorithm("none")) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func rejectsKeyReferenceHeaderParameters() async throws {
        let headers = [
            #"{"alg":"RS256","x5u":"https://evil.example/cert"}"#,
            #"{"alg":"RS256","x5c":["cert"]}"#,
            #"{"alg":"RS256","jku":"https://evil.example/jwks"}"#,
            #"{"alg":"RS256","jwk":{"kty":"RSA"}}"#,
        ]
        let payload = #"{"iss":"https://issuer.example","sub":"123","aud":"client","exp":9999999999,"iat":0}"#

        for header in headers {
            let client = try await self.makeClient(
                configuration: self.configuration(fetchUserInfo: false),
                token: self.rawToken(header: header, payload: payload),
                jwks: JWKS(keys: [])
            )
            await #expect(throws: OIDCError.self) {
                _ = try await client.exchange(
                    code: "code",
                    codeVerifier: "verifier",
                    nonce: "nonce"
                )
            }
        }
    }

    @Test
    func rejectsMissingKidWithMultipleKeys() async throws {
        let firstKey = P256.Signing.PrivateKey()
        let secondKey = P256.Signing.PrivateKey()
        let firstJWK = try Self.jwk(from: firstKey, kid: "first")
        let secondJWK = try Self.jwk(from: secondKey, kid: "second")

        let signingKeys = JWTKeyCollection()
        try await signingKeys.add(jwk: firstJWK)
        let token = try await signingKeys.sign(self.claims())

        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: false),
            token: token,
            jwks: JWKS(keys: [firstJWK, secondJWK])
        )

        await #expect(throws: OIDCError.missingJWKSKey(kid: "<missing>")) {
            _ = try await client.exchange(
                code: "code",
                codeVerifier: "verifier",
                nonce: "nonce"
            )
        }
    }

    @Test
    func acceptsMatchingAtHash() async throws {
        let accessToken = "access"
        let bytes = Array(SHA256.hash(data: Data(accessToken.utf8)))
        let atHash = Data(bytes.prefix(bytes.count / 2)).base64URLEncodedString()

        let client = try await self.makeClient(
            claims: self.claims(accessTokenHash: atHash),
            accessToken: accessToken
        )
        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )
        #expect(identity.subject.subject == "123")
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
    func mergesUserInfoClaims() async throws {
        let client = try await self.makeClient(
            claims: self.claims(),
            fetchUserInfo: true,
            userInfo: OIDCClaims([
                "sub": .string("123"),
                "email": .string("userinfo@example.com"),
                "name": .string("UserInfo Name"),
            ])
        )
        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )

        #expect(identity.email == "userinfo@example.com")
        #expect(identity.name == "UserInfo Name")
    }

    @Test
    func ignoresUserInfoFailureWhenConfigured() async throws {
        let signed = try await self.signedToken(claims: self.claims())
        let client = try await self.makeClient(
            configuration: self.configuration(
                fetchUserInfo: true,
                userInfoFailurePolicy: .ignore
            ),
            token: signed.token,
            jwks: signed.jwks,
            userInfo: OIDCClaims(["sub": .string("123")]),
            userInfoStatusCode: 500
        )

        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )
        #expect(identity.email == "user@example.com")
    }

    @Test
    func doesNotMergeMismatchedUserInfoWhenIgnoring() async throws {
        let signed = try await self.signedToken(claims: self.claims())
        let client = try await self.makeClient(
            configuration: self.configuration(
                fetchUserInfo: true,
                userInfoFailurePolicy: .ignore
            ),
            token: signed.token,
            jwks: signed.jwks,
            userInfo: OIDCClaims([
                "sub": .string("other"),
                "email": .string("attacker@example.com"),
            ])
        )

        let identity = try await client.exchange(
            code: "code",
            codeVerifier: "verifier",
            nonce: "nonce"
        )
        #expect(identity.subject.subject == "123")
        #expect(identity.email == "user@example.com")
    }

    @Test
    func refreshFallsBackToUserInfoWhenNoIDToken() async throws {
        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: true),
            token: nil,
            jwks: JWKS(keys: []),
            userInfo: OIDCClaims([
                "sub": .string("123"),
                "email": .string("user@example.com"),
                "email_verified": .bool(true),
            ])
        )

        let identity = try await client.refresh(refreshToken: "refresh")
        #expect(identity.subject.issuer == "https://issuer.example")
        #expect(identity.subject.subject == "123")
        #expect(identity.email == "user@example.com")
        #expect(identity.emailVerified == true)
    }

    @Test
    func refreshRequiresIDTokenWhenUserInfoDisabled() async throws {
        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: false),
            token: nil,
            jwks: JWKS(keys: [])
        )

        await #expect(throws: OIDCError.missingIDToken) {
            _ = try await client.refresh(refreshToken: "refresh")
        }
    }

    @Test
    func refreshReturnsRotatedRefreshToken() async throws {
        let signed = try await self.signedToken(
            claims: self.claims(nonce: nil)
        )
        let client = try await self.makeClient(
            configuration: self.configuration(fetchUserInfo: false),
            token: signed.token,
            jwks: signed.jwks,
            refreshToken: "rotated"
        )

        let identity = try await client.refresh(refreshToken: "refresh")
        #expect(identity.tokens.refreshToken == "rotated")
    }

    @Test
    func buildsLogoutURL() async throws {
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

        let result = try await client.logoutURL(
            idToken: "id-token",
            postLogoutRedirectURI: URL(string: "https://app.example/bye")
        )
        let url = try #require(result)
        let components = try #require(
            URLComponents(url: url, resolvingAgainstBaseURL: false)
        )
        let items = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).map {
                ($0.name, $0.value ?? "")
            }
        )

        #expect(items["id_token_hint"] == "id-token")
        #expect(items["client_id"] == "client")
        #expect(items["post_logout_redirect_uri"] == "https://app.example/bye")
    }

    @Test
    func returnsNilLogoutURLWithoutEndpoint() async throws {
        let discovery = OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!
        )
        let data = try JSONEncoder().encode(discovery)
        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: data),
            for: self.discoveryURL
        )
        let client = OIDCClient(
            configuration: self.configuration(),
            httpClient: http
        )

        let url = try await client.logoutURL(
            idToken: "id-token",
            postLogoutRedirectURI: nil
        )
        #expect(url == nil)
    }

    @Test
    func rejectsProviderWithoutPKCESupport() async throws {
        let discovery = OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!,
            codeChallengeMethodsSupported: ["plain"]
        )
        let data = try JSONEncoder().encode(discovery)
        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: data),
            for: self.discoveryURL
        )
        let client = OIDCClient(
            configuration: self.configuration(),
            httpClient: http
        )

        await #expect(throws: OIDCError.pkceUnsupported) {
            _ = try await client.authorizationURL(
                state: "state",
                nonce: "nonce",
                codeChallenge: "challenge"
            )
        }
    }

    @Test
    func includesAdditionalAuthorizationParameters() async throws {
        let http = MockOIDCHTTPClient()
        let discovery = self.discovery()
        let data = try JSONEncoder().encode(discovery)
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: data),
            for: self.discoveryURL
        )
        let configuration = OIDCConfiguration(
            issuer: URL(string: "https://issuer.example")!,
            clientID: "client",
            clientSecret: "secret",
            redirectURI: URL(string: "https://client.example/auth/callback")!,
            additionalAuthorizationParameters: ["prompt": "consent"]
        )
        let client = OIDCClient(configuration: configuration, httpClient: http)

        let url = try await client.authorizationURL(
            state: "state",
            nonce: "nonce",
            codeChallenge: "challenge"
        )
        #expect(url.absoluteString.contains("prompt=consent"))
    }

    @Test
    func rejectsUserInfoWithoutEndpoint() async throws {
        let discovery = OIDCDiscovery(
            issuer: "https://issuer.example",
            authorizationEndpoint: URL(string: "https://issuer.example/authorize")!,
            tokenEndpoint: URL(string: "https://issuer.example/token")!,
            jwksURI: URL(string: "https://issuer.example/jwks")!
        )
        let data = try JSONEncoder().encode(discovery)
        let http = MockOIDCHTTPClient()
        await http.setResponse(
            OIDCHTTPResponse(statusCode: 200, body: data),
            for: self.discoveryURL
        )
        let client = OIDCClient(
            configuration: self.configuration(fetchUserInfo: true),
            httpClient: http
        )

        await #expect(throws: OIDCError.self) {
            _ = try await client.userInfo(accessToken: "access")
        }
    }

    @Test
    func propagatesUserInfoFailureWhenConfiguredToFail() async throws {
        let signed = try await self.signedToken(claims: self.claims())
        let client = try await self.makeClient(
            configuration: self.configuration(
                fetchUserInfo: true,
                userInfoFailurePolicy: .fail
            ),
            token: signed.token,
            jwks: signed.jwks,
            userInfo: OIDCClaims(["sub": .string("123")]),
            userInfoStatusCode: 500
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
    func rejectsUnsupportedAlgorithm() async throws {
        let header = #"{"alg":"HS256","kid":"test"}"#
        let payload = #"{"iss":"https://issuer.example","sub":"123","aud":"client","exp":9999999999,"iat":0}"#
        let token = self.rawToken(header: header, payload: payload)

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
        let d = privateKey.rawRepresentation.base64URLEncodedString()
        let publicKey = try ES256PublicKey(backing: privateKey.publicKey)
        guard let x = publicKey.parameters?.x,
              let y = publicKey.parameters?.y else {
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

/// An ID Token payload without the required `iat` claim.
private struct ClaimsWithoutIssuedAt: JWTPayload {
    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var nonce: String?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case nonce
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {}
}
