import Vapor
import VaporOIDCCore

/// Resolves the application's user model from an OIDC identity.
///
/// The library never assumes a user table or a Fluent model. The application
/// provides two closures: one to find or create the user after login, and one
/// to restore the user from the stable `iss` + `sub` pair on later requests.
public struct OIDCUserResolver<User: Authenticatable>: Sendable {
    /// Called after a successful login. Find or create the application's user.
    public let resolve: @Sendable (OIDCIdentity, Request) async throws -> User

    /// Called on each request to restore the user from the session.
    ///
    /// Return `nil` to log the user out.
    public let restore: @Sendable (OIDCSubject, Request) async throws -> User?

    /// Creates a resolver.
    public init(
        resolve: @escaping @Sendable (OIDCIdentity, Request) async throws -> User,
        restore: @escaping @Sendable (OIDCSubject, Request) async throws -> User?
    ) {
        self.resolve = resolve
        self.restore = restore
    }
}
