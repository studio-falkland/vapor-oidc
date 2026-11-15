import Vapor
import VaporOIDCCore

/// Restores the application's user from the OIDC session on each request.
public struct OIDCSessionAuthenticator<User: Authenticatable>: RequestAuthenticator {
    let oidc: OIDC<User>

    public func authenticate(request: Request) async throws {
        // Skip when another authenticator already logged the user in.
        guard !request.auth.has(User.self) else {
            return
        }

        // Skip anonymous requests that have no session yet.
        guard request.hasSession else {
            return
        }

        // Read the stable subject from the session.
        guard let subject = self.oidc.session.subject(for: request) else {
            return
        }

        // Restore the user, or clear the session when the user is gone.
        guard let user = try await self.oidc.resolver.restore(subject, request) else {
            self.oidc.session.clear(for: request)
            return
        }

        request.auth.login(user)
    }
}
