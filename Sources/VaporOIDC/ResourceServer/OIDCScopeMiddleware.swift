import HTTPTypes
import Vapor
import VaporOIDCCore

/// Enforces access-token scopes on a route group.
public struct OIDCScopeMiddleware: Middleware {
    private let scopes: Set<String>

    /// Creates a scope middleware.
    public init(_ scopes: String...) {
        self.scopes = Set(scopes)
    }

    public func respond(
        to request: Request,
        chainingTo next: any Responder
    ) async throws -> Response {
        // Require a validated access token.
        guard let token = request.auth.get(OIDCAccessToken.self) else {
            var headers = HTTPFields()
            headers[.wwwAuthenticate] = "Bearer"
            throw Abort(.unauthorized, headers: headers, reason: "Missing access token.")
        }

        // Require every configured scope.
        let missing = self.scopes.subtracting(token.scopes)
        guard missing.isEmpty else {
            var headers = HTTPFields()
            let scope = missing.sorted().joined(separator: " ")
            headers[.wwwAuthenticate] = "Bearer error=\"insufficient_scope\", scope=\"\(scope)\""
            throw Abort(.forbidden, headers: headers, reason: "Missing scope: \(scope)")
        }

        return try await next.respond(to: request)
    }
}

extension Request {
    /// Requires a scope on the authenticated access token.
    public func requireScope(_ scope: String) throws {
        let token = try self.auth.require(OIDCAccessToken.self)
        guard token.hasScope(scope) else {
            throw OIDCError.insufficientScope(
                required: scope,
                granted: token.scopes
            )
        }
    }
}
