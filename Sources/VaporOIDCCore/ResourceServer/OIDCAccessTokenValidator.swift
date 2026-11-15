/// Validates an access token presented to the resource server.
public protocol OIDCAccessTokenValidator: Sendable {
    /// Validates a bearer token and returns its claims.
    func validate(_ token: String) async throws -> OIDCAccessToken
}
