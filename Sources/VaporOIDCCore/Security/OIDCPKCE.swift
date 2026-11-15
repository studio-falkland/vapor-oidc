#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// A PKCE code verifier and its `S256` challenge.
public struct OIDCPKCE: Sendable {
    /// The code verifier.
    public let verifier: String

    /// The `S256` code challenge derived from the verifier.
    public var challenge: String {
        Self.challenge(for: self.verifier)
    }

    /// Creates a PKCE pair from an existing verifier.
    public init(verifier: String) {
        self.verifier = verifier
    }

    /// Generates a new PKCE pair.
    public static func generate() -> OIDCPKCE {
        // Generate 32 random bytes and base64url-encode them.
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<32).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        }
        return OIDCPKCE(verifier: Data(bytes).base64URLEncodedString())
    }

    public static func challenge(for verifier: String) -> String {
        // S256: base64url(SHA256(verifier)).
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }
}
