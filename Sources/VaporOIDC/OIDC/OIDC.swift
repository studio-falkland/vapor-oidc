import Logging
import Vapor
import VaporOIDCCore

/// Owns the OIDC provider, user resolver, state store, session, and routes.
///
/// Create one in `configure`, add ``sessionAuthenticator`` to the middleware,
/// and register the routes under a group:
///
/// ```swift
/// let oidc = OIDC<User>(provider: ..., resolver: ...)
/// app.middleware.use(app.sessionsMiddleware)
/// app.middleware.use(oidc.sessionAuthenticator)
/// try await app.grouped("auth").register(collection: oidc)
/// ```
public struct OIDC<User: Authenticatable>: Sendable {
    /// The OIDC provider.
    public let provider: any OIDCProvider

    /// The application's user-model hook.
    public let resolver: OIDCUserResolver<User>

    /// The adapter options.
    public let options: OIDCOptions

    /// The state store.
    public let stateStore: any OIDCStateStore

    /// The session helper.
    public let session: OIDCSession

    /// The logger.
    public let logger: Logger

    /// Creates an OIDC holder.
    public init(
        provider: any OIDCProvider,
        resolver: OIDCUserResolver<User>,
        options: OIDCOptions = .init(),
        stateStore: any OIDCStateStore = SessionOIDCStateStore(),
        logger: Logger = Logger.current
    ) {
        self.provider = provider
        self.resolver = resolver
        self.options = options
        self.stateStore = stateStore
        self.session = OIDCSession(keys: options.sessionKeys)
        self.logger = logger
    }

    /// The middleware that restores the user from the session.
    public var sessionAuthenticator: OIDCSessionAuthenticator<User> {
        OIDCSessionAuthenticator(oidc: self)
    }

    /// Starts the authorization code flow.
    public func login(_ request: Request) async throws -> Response {
        // Read the optional post-login redirect target.
        let redirect = request.query[String.self, at: self.options.redirectQueryParameter]

        // Generate state, nonce, and PKCE, then persist them in the session.
        let state = OIDCState.generate(
            issuer: self.provider.configuration.issuer.absoluteString,
            redirectAfterLogin: redirect,
            usePKCE: self.provider.configuration.usePKCE
        )
        try self.stateStore.save(state, for: request)

        // Build the provider URL and send the browser there.
        let url = try await self.provider.authorizationURL(
            state: state.state,
            nonce: self.provider.configuration.useNonce ? state.nonce : nil,
            codeChallenge: state.codeChallenge
        )
        return request.redirect(to: url.absoluteString)
    }

    /// Handles the authorization response.
    public func callback(_ request: Request) async throws -> Response {
        // Surface provider errors before looking for a code.
        if let error = request.query[String.self, at: "error"] {
            let description = request.query[String.self, at: "error_description"]
            throw OIDCError.authorizationFailed(error: error, description: description)
        }

        // Read the code and state, then consume the state once.
        guard let code = request.query[String.self, at: "code"] else {
            throw OIDCError.missingCode
        }
        guard let stateValue = request.query[String.self, at: "state"] else {
            throw OIDCError.invalidState
        }
        guard let state = try self.stateStore.consume(state: stateValue, for: request) else {
            throw OIDCError.invalidState
        }

        // Bind the response to the issuer that started the flow.
        if let issuer = request.query[String.self, at: "iss"], issuer != state.issuer {
            throw OIDCError.issuerMismatch(expected: state.issuer, actual: issuer)
        }

        // Exchange the code, resolve the user, and log them in.
        let identity = try await self.provider.exchange(
            code: code,
            codeVerifier: state.codeVerifier,
            nonce: self.provider.configuration.useNonce ? state.nonce : nil
        )
        let user = try await self.resolver.resolve(identity, request)
        request.auth.login(user)

        // Persist the stable subject and, optionally, the ID token for logout.
        self.session.store(
            subject: identity.subject,
            idToken: self.options.storeIDTokenForLogout ? identity.tokens.idToken : nil,
            for: request
        )

        // Redirect to the sanitized post-login target.
        return request.redirect(to: self.options.sanitizeRedirect(state.redirectAfterLogin))
    }

    /// Logs the user out and, when possible, redirects to the provider.
    public func logout(_ request: Request) async throws -> Response {
        // Read the ID token before clearing the session.
        let idToken = self.session.idToken(for: request)
        self.session.clear(for: request)
        request.auth.logout(User.self)

        // Prefer the provider's end-session endpoint when available.
        if let idToken,
           let url = try await self.provider.logoutURL(
               idToken: idToken,
               postLogoutRedirectURI: self.options.postLogoutRedirectURI
           ) {
            return request.redirect(to: url.absoluteString)
        }

        // Otherwise redirect to the configured post-logout target.
        return request.redirect(
            to: self.options.postLogoutRedirectURI?.absoluteString
                ?? self.options.defaultRedirectAfterLogin
        )
    }
}

extension OIDC: RouteCollection {
    public func boot(routes: any RoutesBuilder) async throws {
        // Register the flow relative to the group the app chooses.
        routes.get("login", use: self.login)
        routes.get("callback", use: self.callback)
        routes.post("logout", use: self.logout)
    }
}
