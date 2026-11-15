#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The per-login state stored between the authorization request and callback.
public struct OIDCState: Codable, Sendable {
    /// The `state` parameter.
    public let state: String

    /// The `nonce` parameter.
    public let nonce: String

    /// The PKCE code verifier.
    public let codeVerifier: String?

    /// The issuer the authorization request was sent to.
    public let issuer: String

    /// Where to send the user after a successful login.
    public let redirectAfterLogin: String?

    /// When the state was created.
    public let createdAt: Date

    /// The PKCE code challenge derived from the verifier.
    public var codeChallenge: String? {
        self.codeVerifier.map(OIDCPKCE.challenge(for:))
    }

    /// Creates a state value.
    public init(
        state: String,
        nonce: String,
        codeVerifier: String?,
        issuer: String,
        redirectAfterLogin: String?,
        createdAt: Date
    ) {
        self.state = state
        self.nonce = nonce
        self.codeVerifier = codeVerifier
        self.issuer = issuer
        self.redirectAfterLogin = redirectAfterLogin
        self.createdAt = createdAt
    }

    /// Generates a new state value.
    public static func generate(
        issuer: String,
        redirectAfterLogin: String?,
        usePKCE: Bool = true
    ) -> OIDCState {
        // Generate independent random state and nonce values.
        OIDCState(
            state: Self.randomToken(),
            nonce: Self.randomToken(),
            codeVerifier: usePKCE ? OIDCPKCE.generate().verifier : nil,
            issuer: issuer,
            redirectAfterLogin: redirectAfterLogin,
            createdAt: Date()
        )
    }

    private static func randomToken() -> String {
        // Generate 32 random bytes and base64url-encode them.
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<32).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        }
        return Data(bytes).base64URLEncodedString()
    }
}
