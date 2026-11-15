#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The adapter-level options for an ``OIDC`` holder.
public struct OIDCOptions: Sendable {
    /// Where to send the user when no valid redirect target is available.
    public var defaultRedirectAfterLogin: String

    /// The RP-initiated logout redirect URI.
    public var postLogoutRedirectURI: URL?

    /// The query parameter that carries the post-login redirect target.
    public var redirectQueryParameter: String

    /// Whether to store the ID token in the session for logout.
    public var storeIDTokenForLogout: Bool

    /// The session keys.
    public var sessionKeys: OIDCSessionKeys

    /// Origins that are allowed as absolute post-login redirect targets.
    public var allowedRedirectOrigins: Set<String>

    /// Creates options.
    public init(
        defaultRedirectAfterLogin: String = "/",
        postLogoutRedirectURI: URL? = nil,
        redirectQueryParameter: String = "redirect",
        storeIDTokenForLogout: Bool = true,
        sessionKeys: OIDCSessionKeys = .init(),
        allowedRedirectOrigins: Set<String> = []
    ) {
        self.defaultRedirectAfterLogin = defaultRedirectAfterLogin
        self.postLogoutRedirectURI = postLogoutRedirectURI
        self.redirectQueryParameter = redirectQueryParameter
        self.storeIDTokenForLogout = storeIDTokenForLogout
        self.sessionKeys = sessionKeys
        self.allowedRedirectOrigins = allowedRedirectOrigins
    }

    /// Returns a safe redirect target.
    ///
    /// Relative paths are allowed. Absolute URLs are allowed only when their
    /// origin is in ``allowedRedirectOrigins``. Everything else falls back to
    /// ``defaultRedirectAfterLogin``.
    public func sanitizeRedirect(_ value: String?) -> String {
        // Fall back when no target was supplied.
        guard let value, !value.isEmpty else {
            return self.defaultRedirectAfterLogin
        }

        // Allow relative paths, but not protocol-relative URLs.
        if value.hasPrefix("/") && !value.hasPrefix("//") {
            return value
        }

        // Allow absolute URLs only when their origin is trusted.
        guard let url = URL(string: value),
              let scheme = url.scheme,
              let host = url.host,
              scheme == "https" || scheme == "http" else {
            return self.defaultRedirectAfterLogin
        }

        let origin = "\(scheme)://\(host)"
        guard self.allowedRedirectOrigins.contains(origin) else {
            return self.defaultRedirectAfterLogin
        }
        return value
    }
}
