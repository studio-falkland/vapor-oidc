import Vapor
import VaporOIDCCore

/// Resolves the application's user model from a validated access token.
public struct OIDCBearerUserResolver<User: Authenticatable>: Sendable {
    /// Maps an access token to the application's user.
    ///
    /// Return `nil` when the token does not identify a known user.
    public let resolve: @Sendable (OIDCAccessToken, Request) async throws -> User?

    /// Creates a resolver.
    public init(
        resolve: @escaping @Sendable (OIDCAccessToken, Request) async throws -> User?
    ) {
        self.resolve = resolve
    }
}
