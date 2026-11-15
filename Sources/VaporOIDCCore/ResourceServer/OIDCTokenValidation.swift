/// How the resource server validates an access token.
public enum OIDCTokenValidation: Sendable {
    /// Validate the token as a JWT.
    case jwt

    /// Validate the token with the provider's introspection endpoint.
    case introspection

    /// Use JWT validation when the token looks like a JWT, otherwise introspect.
    case automatic
}
