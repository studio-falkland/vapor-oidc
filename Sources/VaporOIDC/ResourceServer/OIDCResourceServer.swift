import Logging
import Vapor
import VaporOIDCCore

/// Owns the resource-server validator, user resolver, bearer authenticator, and
/// protected-resource metadata route.
public struct OIDCResourceServer<User: Authenticatable>: Sendable, RouteCollection {
    /// The resource-server configuration.
    public let configuration: OIDCResourceServerConfiguration

    /// The access-token validator.
    public let validator: any OIDCAccessTokenValidator

    /// The application's user-model hook.
    public let resolver: OIDCBearerUserResolver<User>

    /// The logger.
    public let logger: Logger

    /// Creates a resource server.
    public init(
        configuration: OIDCResourceServerConfiguration,
        validator: any OIDCAccessTokenValidator,
        resolver: OIDCBearerUserResolver<User>,
        logger: Logger = Logger.current
    ) {
        self.configuration = configuration
        self.validator = validator
        self.resolver = resolver
        self.logger = logger
    }

    /// The middleware that authenticates bearer tokens.
    public var bearerAuthenticator: OIDCBearerAuthenticator<User> {
        OIDCBearerAuthenticator(resourceServer: self)
    }

    /// The protected-resource metadata route.
    public var protectedResourceMetadata: OIDCProtectedResourceMetadata {
        OIDCProtectedResourceMetadata(
            resource: self.configuration.audience,
            authorizationServers: [self.configuration.issuer.absoluteString],
            scopesSupported: self.configuration.requiredScopes.sorted()
        )
    }

    public func boot(routes: any RoutesBuilder) async throws {
        // Register the well-known metadata endpoint automatically.
        try await routes.register(collection: self.protectedResourceMetadata)
    }
}
