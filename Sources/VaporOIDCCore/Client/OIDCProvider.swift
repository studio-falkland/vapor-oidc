#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The operations an OIDC provider must support.
public protocol OIDCProvider: Sendable {
    /// The client configuration.
    var configuration: OIDCConfiguration { get }

    /// Fetches and validates the discovery document.
    func discovery() async throws -> OIDCDiscovery

    /// Builds the authorization URL.
    func authorizationURL(
        state: String,
        nonce: String?,
        codeChallenge: String?
    ) async throws -> URL

    /// Exchanges an authorization code for tokens and validates the ID Token.
    func exchange(
        code: String,
        codeVerifier: String?,
        nonce: String?
    ) async throws -> OIDCIdentity

    /// Refreshes an access token.
    func refresh(refreshToken: String) async throws -> OIDCIdentity

    /// Fetches the UserInfo claims.
    func userInfo(accessToken: String) async throws -> OIDCClaims

    /// Builds the RP-initiated logout URL.
    func logoutURL(
        idToken: String,
        postLogoutRedirectURI: URL?
    ) async throws -> URL?
}
