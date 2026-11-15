import Logging
import Vapor
import VaporOIDCCore

extension Application {
    /// Creates an ``OIDC`` holder backed by the application client.
    public func oidc<User: Authenticatable>(
        configuration: OIDCConfiguration,
        resolver: OIDCUserResolver<User>,
        options: OIDCOptions = .init(),
        stateStore: any OIDCStateStore = SessionOIDCStateStore(),
        logger: Logger = Logger.current
    ) -> OIDC<User> {
        // Build the production provider with the application client.
        OIDC(
            provider: OIDCClient(
                configuration: configuration,
                httpClient: VaporOIDCHTTPClient(client: self.client),
                logger: logger
            ),
            resolver: resolver,
            options: options,
            stateStore: stateStore,
            logger: logger
        )
    }
}
