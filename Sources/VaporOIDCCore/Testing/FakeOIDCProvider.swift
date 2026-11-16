#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A test double for ``OIDCProvider``.
public actor FakeOIDCProvider: OIDCProvider {
    public nonisolated let configuration: OIDCConfiguration

    /// The authorization requests that were built.
    public private(set) var authorizationRequests: [
        (state: String, nonce: String?, codeChallenge: String?)
    ] = []

    /// The codes that were exchanged.
    public private(set) var exchangedCodes: [
        (code: String, codeVerifier: String?, nonce: String?)
    ] = []

    /// The refresh tokens that were used.
    public private(set) var refreshedTokens: [String] = []

    /// The access tokens used for UserInfo.
    public private(set) var userInfoRequests: [String] = []

    /// The logout requests that were built.
    public private(set) var logoutRequests: [
        (idToken: String, postLogoutRedirectURI: URL?)
    ] = []

    /// The discovery result.
    public var discoveryResult: Result<OIDCDiscovery, OIDCError>

    /// The identity result.
    public var identityResult: Result<OIDCIdentity, OIDCError>

    /// The UserInfo result.
    public var userInfoResult: Result<OIDCClaims, OIDCError>

    /// The logout URL result.
    public var logoutURLResult: URL?

    /// Creates a fake provider.
    public init(
        configuration: OIDCConfiguration,
        discovery: OIDCDiscovery,
        identity: OIDCIdentity
    ) {
        self.configuration = configuration
        self.discoveryResult = .success(discovery)
        self.identityResult = .success(identity)
        self.userInfoResult = .success(identity.claims)
        self.logoutURLResult = nil
    }

    /// Sets the logout URL returned by ``logoutURL(idToken:postLogoutRedirectURI:)``.
    public func setLogoutURLResult(_ url: URL?) {
        self.logoutURLResult = url
    }

    public func discovery() async throws -> OIDCDiscovery {
        try self.discoveryResult.get()
    }

    public func authorizationURL(
        state: String,
        nonce: String?,
        codeChallenge: String?
    ) async throws -> URL {
        // Record the request and build a deterministic URL.
        self.authorizationRequests.append((state, nonce, codeChallenge))
        var components = URLComponents(string: "https://provider.example/authorize")
        components?.queryItems = [
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
        ]
        guard let url = components?.url else {
            throw OIDCError.invalidDiscoveryDocument("Unable to build the fake authorization URL.")
        }
        return url
    }

    public func exchange(
        code: String,
        codeVerifier: String?,
        nonce: String?
    ) async throws -> OIDCIdentity {
        // Record the exchange and return the canned identity.
        self.exchangedCodes.append((code, codeVerifier, nonce))
        return try self.identityResult.get()
    }

    public func refresh(refreshToken: String) async throws -> OIDCIdentity {
        // Record the refresh and return the canned identity.
        self.refreshedTokens.append(refreshToken)
        return try self.identityResult.get()
    }

    public func userInfo(accessToken: String) async throws -> OIDCClaims {
        // Record the request and return the canned claims.
        self.userInfoRequests.append(accessToken)
        return try self.userInfoResult.get()
    }

    public func logoutURL(
        idToken: String,
        postLogoutRedirectURI: URL?
    ) async throws -> URL? {
        // Record the request and return the canned URL.
        self.logoutRequests.append((idToken, postLogoutRedirectURI))
        return self.logoutURLResult
    }
}
