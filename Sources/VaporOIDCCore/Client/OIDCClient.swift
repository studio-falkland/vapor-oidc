#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import JWTKit
import Logging

/// The production OIDC provider.
public actor OIDCClient: OIDCProvider {
    public nonisolated let configuration: OIDCConfiguration

    private let httpClient: any OIDCHTTPClient
    private let logger: Logger
    private let discoveryLoader: OIDCDiscoveryLoader
    private let jwksLoader: OIDCJWKSLoader

    /// Creates a client.
    public init(
        configuration: OIDCConfiguration,
        httpClient: any OIDCHTTPClient,
        logger: Logger = Logger.current
    ) {
        self.configuration = configuration
        self.httpClient = httpClient
        self.logger = logger

        let discoveryLoader = OIDCDiscoveryLoader(
            issuer: configuration.issuer,
            discoveryURL: configuration.discoveryURL,
            requireHTTPS: configuration.requireHTTPS,
            httpClient: httpClient,
            logger: logger
        )
        self.discoveryLoader = discoveryLoader
        self.jwksLoader = OIDCJWKSLoader(
            discoveryLoader: discoveryLoader,
            cacheDuration: configuration.jwksCacheDuration,
            requireHTTPS: configuration.requireHTTPS,
            httpClient: httpClient,
            logger: logger
        )
    }

    public func discovery() async throws -> OIDCDiscovery {
        try await self.discoveryLoader.load()
    }

    public func authorizationURL(
        state: String,
        nonce: String?,
        codeChallenge: String?
    ) async throws -> URL {
        let discovery = try await self.discovery()

        // Require the provider to advertise PKCE S256 when PKCE is enabled.
        if self.configuration.usePKCE {
            guard let methods = discovery.codeChallengeMethodsSupported,
                  methods.contains("S256") else {
                throw OIDCError.pkceUnsupported
            }
        }

        // Start from the provider's authorization endpoint.
        var components = URLComponents(
            url: discovery.authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )
        var items = components?.queryItems ?? []

        // Add the required authorization parameters.
        items.append(URLQueryItem(name: "response_type", value: "code"))
        items.append(URLQueryItem(name: "client_id", value: self.configuration.clientID))
        items.append(URLQueryItem(name: "redirect_uri", value: self.configuration.redirectURI.absoluteString))
        items.append(URLQueryItem(name: "scope", value: self.configuration.scopes.joined(separator: " ")))
        items.append(URLQueryItem(name: "state", value: state))

        // Add the nonce and PKCE challenge when enabled.
        if let nonce {
            items.append(URLQueryItem(name: "nonce", value: nonce))
        }
        if let codeChallenge {
            items.append(URLQueryItem(name: "code_challenge", value: codeChallenge))
            items.append(URLQueryItem(name: "code_challenge_method", value: "S256"))
        }

        // Add any provider-specific parameters.
        for (name, value) in self.configuration.additionalAuthorizationParameters {
            items.append(URLQueryItem(name: name, value: value))
        }
        components?.queryItems = items

        guard let url = components?.url else {
            throw OIDCError.invalidDiscoveryDocument("Unable to build the authorization URL.")
        }
        return url
    }

    public func exchange(
        code: String,
        codeVerifier: String?,
        nonce: String?
    ) async throws -> OIDCIdentity {
        let discovery = try await self.discovery()

        // Build the authorization code token request.
        var body = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.configuration.redirectURI.absoluteString,
            "client_id": self.configuration.clientID,
        ]
        if let codeVerifier {
            body["code_verifier"] = codeVerifier
        }

        // Send the request and require a successful response.
        let request = try self.tokenRequest(discovery: discovery, body: body)
        let response = try await self.httpClient.send(request)
        guard response.statusCode == 200 else {
            throw OIDCError.tokenExchangeFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        // Decode the token response.
        let tokenResponse: OIDCTokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(OIDCTokenResponse.self, from: response.body)
        } catch {
            throw OIDCError.invalidIDToken("Unable to decode the token response: \(error)")
        }

        // Require and validate the ID token.
        guard let idToken = tokenResponse.idToken else {
            throw OIDCError.missingIDToken
        }
        let claims = try await self.verifyIDToken(
            idToken,
            nonce: nonce,
            accessToken: tokenResponse.accessToken
        )

        // Merge UserInfo claims when configured.
        let userInfo = try await self.fetchUserInfoIfNeeded(
            accessToken: tokenResponse.accessToken,
            expectedSubject: claims.subject.value
        )
        return self.identity(from: claims, userInfo: userInfo, tokenResponse: tokenResponse)
    }

    public func refresh(refreshToken: String) async throws -> OIDCIdentity {
        let discovery = try await self.discovery()

        // Build the refresh token request.
        let body = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": self.configuration.clientID,
        ]

        // Send the request and require a successful response.
        let request = try self.tokenRequest(discovery: discovery, body: body)
        let response = try await self.httpClient.send(request)
        guard response.statusCode == 200 else {
            throw OIDCError.tokenExchangeFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        // Decode the token response.
        let tokenResponse: OIDCTokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(OIDCTokenResponse.self, from: response.body)
        } catch {
            throw OIDCError.invalidIDToken("Unable to decode the refresh response: \(error)")
        }

        // When an ID token is returned, validate it without requiring a nonce.
        if let idToken = tokenResponse.idToken {
            let claims = try await self.verifyIDToken(
                idToken,
                nonce: nil,
                accessToken: tokenResponse.accessToken,
                requireNonce: false
            )
            let userInfo = try await self.fetchUserInfoIfNeeded(
                accessToken: tokenResponse.accessToken,
                expectedSubject: claims.subject.value
            )
            return self.identity(from: claims, userInfo: userInfo, tokenResponse: tokenResponse)
        }

        // Otherwise fall back to UserInfo for the subject.
        guard self.configuration.fetchUserInfo else {
            throw OIDCError.missingIDToken
        }
        let userInfo = try await self.userInfo(accessToken: tokenResponse.accessToken)
        guard let subject = userInfo.string("sub") else {
            throw OIDCError.userInfoFailed(
                statusCode: 200,
                body: "The UserInfo response is missing the sub claim."
            )
        }

        return OIDCIdentity(
            subject: OIDCSubject(
                issuer: self.configuration.issuer.absoluteString,
                subject: subject
            ),
            email: userInfo.string("email"),
            emailVerified: userInfo.bool("email_verified"),
            name: userInfo.string("name"),
            preferredUsername: userInfo.string("preferred_username"),
            picture: userInfo.string("picture").flatMap(URL.init(string:)),
            claims: userInfo,
            tokens: OIDCTokens(
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
                idToken: nil,
                tokenType: tokenResponse.tokenType,
                expiresAt: tokenResponse.expiresIn.map {
                    Date().addingTimeInterval(TimeInterval($0))
                },
                scope: tokenResponse.scope
            )
        )
    }

    public func userInfo(accessToken: String) async throws -> OIDCClaims {
        let discovery = try await self.discovery()
        guard let endpoint = discovery.userinfoEndpoint else {
            throw OIDCError.userInfoFailed(
                statusCode: 0,
                body: "The provider does not expose a UserInfo endpoint."
            )
        }

        // Send the access token in the Authorization header.
        let response = try await self.httpClient.send(
            OIDCHTTPRequest(
                method: "GET",
                url: endpoint,
                headers: ["Authorization": "Bearer \(accessToken)"]
            )
        )
        guard response.statusCode == 200 else {
            throw OIDCError.userInfoFailed(
                statusCode: response.statusCode,
                body: String(decoding: response.body, as: UTF8.self)
            )
        }

        // Decode the claims.
        do {
            return try JSONDecoder().decode(OIDCClaims.self, from: response.body)
        } catch {
            throw OIDCError.userInfoFailed(
                statusCode: response.statusCode,
                body: String(describing: error)
            )
        }
    }

    public func logoutURL(
        idToken: String,
        postLogoutRedirectURI: URL?
    ) async throws -> URL? {
        let discovery = try await self.discovery()
        guard let endpoint = discovery.endSessionEndpoint else {
            return nil
        }

        // Build the RP-initiated logout URL.
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        var items = components?.queryItems ?? []
        items.append(URLQueryItem(name: "id_token_hint", value: idToken))
        items.append(URLQueryItem(name: "client_id", value: self.configuration.clientID))
        if let postLogoutRedirectURI {
            items.append(URLQueryItem(
                name: "post_logout_redirect_uri",
                value: postLogoutRedirectURI.absoluteString
            ))
        }
        components?.queryItems = items
        return components?.url
    }

    // MARK: - Private

    private func tokenRequest(
        discovery: OIDCDiscovery,
        body: [String: String]
    ) throws -> OIDCHTTPRequest {
        var headers = ["Content-Type": "application/x-www-form-urlencoded"]
        var body = body

        // Apply the configured client authentication method.
        try OIDCFormRequest.applyClientAuthentication(
            headers: &headers,
            body: &body,
            clientID: self.configuration.clientID,
            clientSecret: self.configuration.clientSecret,
            method: self.configuration.tokenEndpointAuthenticationMethod
        )

        return OIDCHTTPRequest(
            method: "POST",
            url: discovery.tokenEndpoint,
            headers: headers,
            body: OIDCFormRequest.encode(body)
        )
    }

    private func verifyIDToken(
        _ token: String,
        nonce: String?,
        accessToken: String,
        requireNonce: Bool = true
    ) async throws -> IDTokenClaims {
        // Decode the header and reject unsafe algorithms and key references.
        let header = try OIDCJWTHeader.decode(token)
        try header.validate(allowedAlgorithms: self.configuration.allowedIDTokenAlgorithms)

        // Require a kid when the JWKS has multiple keys.
        if header.kid == nil, try await self.jwksLoader.requiresKeyIdentifier() {
            throw OIDCError.missingJWKSKey(kid: "<missing>")
        }

        // Verify the signature, refreshing the JWKS once on failure.
        let claims: IDTokenClaims
        do {
            claims = try await self.jwksLoader.verify(token, as: IDTokenClaims.self)
        } catch {
            throw OIDCError.invalidIDToken(String(describing: error))
        }

        // Validate the issuer and audience.
        try OIDCClaimValidation.validateIssuer(
            claims.issuer.value,
            expected: self.configuration.issuer.absoluteString
        )
        try OIDCClaimValidation.validateAudience(
            claims.audience.value,
            expected: self.configuration.clientID,
            trusted: self.configuration.trustedAudiences
        )
        if let authorizedParty = claims.authorizedParty,
           authorizedParty != self.configuration.clientID {
            throw OIDCError.audienceMismatch
        }

        // Validate the time-based claims with clock skew.
        let skew = self.configuration.clockSkew
        try OIDCClaimValidation.validateExpiration(
            claims.expiration.value,
            clockSkew: skew
        )
        try OIDCClaimValidation.validateIssuedAt(
            claims.issuedAt?.value,
            clockSkew: skew
        )
        try OIDCClaimValidation.validateNotBefore(
            claims.notBefore?.value,
            clockSkew: skew
        )

        // Validate the nonce when the flow requires it.
        if requireNonce && self.configuration.useNonce {
            guard let nonce, claims.nonce == nonce else {
                throw OIDCError.nonceMismatch
            }
        }

        // Validate at_hash when the provider included it.
        if let atHash = claims.accessTokenHash {
            guard Self.verifyAccessTokenHash(
                atHash,
                accessToken: accessToken,
                algorithm: header.alg
            ) else {
                throw OIDCError.invalidIDToken("The at_hash claim does not match the access token.")
            }
        }

        return claims
    }

    private func fetchUserInfoIfNeeded(
        accessToken: String,
        expectedSubject: String
    ) async throws -> OIDCClaims? {
        guard self.configuration.fetchUserInfo else {
            return nil
        }

        do {
            // Fetch the claims and require the subject to match.
            let claims = try await self.userInfo(accessToken: accessToken)
            guard claims.string("sub") == expectedSubject else {
                throw OIDCError.userInfoSubjectMismatch(
                    expected: expectedSubject,
                    actual: claims.string("sub") ?? ""
                )
            }
            return claims
        } catch {
            // Apply the configured failure policy.
            switch self.configuration.userInfoFailurePolicy {
            case .fail:
                throw error
            case .ignore:
                self.logger.warning("UserInfo request failed: \(error)")
                return nil
            }
        }
    }

    private func identity(
        from claims: IDTokenClaims,
        userInfo: OIDCClaims?,
        tokenResponse: OIDCTokenResponse
    ) -> OIDCIdentity {
        // Start with the ID Token claims.
        var merged = OIDCClaims()
        merged["iss"] = .string(claims.issuer.value)
        merged["sub"] = .string(claims.subject.value)
        if let email = claims.email {
            merged["email"] = .string(email)
        }
        if let emailVerified = claims.emailVerified {
            merged["email_verified"] = .bool(emailVerified)
        }
        if let name = claims.name {
            merged["name"] = .string(name)
        }
        if let preferredUsername = claims.preferredUsername {
            merged["preferred_username"] = .string(preferredUsername)
        }
        if let picture = claims.picture {
            merged["picture"] = .string(picture)
        }

        // Let UserInfo override overlapping claims.
        if let userInfo {
            for (key, value) in userInfo.values {
                merged[key] = value
            }
        }

        // Compute the access token expiration.
        let expiresAt = tokenResponse.expiresIn.map {
            Date().addingTimeInterval(TimeInterval($0))
        }

        return OIDCIdentity(
            subject: OIDCSubject(
                issuer: claims.issuer.value,
                subject: claims.subject.value
            ),
            email: merged.string("email"),
            emailVerified: merged.bool("email_verified"),
            name: merged.string("name"),
            preferredUsername: merged.string("preferred_username"),
            picture: merged.string("picture").flatMap(URL.init(string:)),
            claims: merged,
            tokens: OIDCTokens(
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
                idToken: tokenResponse.idToken,
                tokenType: tokenResponse.tokenType,
                expiresAt: expiresAt,
                scope: tokenResponse.scope
            )
        )
    }

    private static func verifyAccessTokenHash(
        _ atHash: String,
        accessToken: String,
        algorithm: String
    ) -> Bool {
        // Hash the access token with the ID Token's algorithm.
        let data = Data(accessToken.utf8)
        let digest: [UInt8]
        switch algorithm {
        case "RS256", "ES256", "PS256":
            digest = Array(SHA256.hash(data: data))
        case "RS384", "ES384", "PS384":
            digest = Array(SHA384.hash(data: data))
        case "RS512", "ES512", "PS512":
            digest = Array(SHA512.hash(data: data))
        default:
            return false
        }

        // Compare the left-most half of the digest.
        let expected = Data(digest.prefix(digest.count / 2)).base64URLEncodedString()
        return atHash == expected
    }
}
