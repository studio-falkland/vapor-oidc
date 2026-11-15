import HTTPTypes
import Vapor
import VaporOIDCCore

/// Authenticates requests that carry an OAuth 2.1 bearer token.
public struct OIDCBearerAuthenticator<User: Authenticatable>: RequestAuthenticator {
    let resourceServer: OIDCResourceServer<User>

    public func authenticate(request: Request) async throws {
        // Require a bearer token on this route group.
        guard let bearer = request.headers.bearerAuthorization else {
            throw self.unauthorized(
                OIDCError.invalidAccessToken("Missing bearer token.")
            )
        }

        // Validate the token.
        let token: OIDCAccessToken
        do {
            token = try await self.resourceServer.validator.validate(bearer.token)
        } catch {
            throw self.unauthorized(error)
        }

        // Enforce the resource server's required scopes.
        let missing = self.resourceServer.configuration.requiredScopes
            .subtracting(token.scopes)
        guard missing.isEmpty else {
            throw self.insufficientScope(missing)
        }

        // Resolve the application's user.
        guard let user = try await self.resourceServer.resolver.resolve(token, request) else {
            throw self.unauthorized(
                OIDCError.invalidAccessToken("No user matches the access token.")
            )
        }

        request.auth.login(token)
        request.auth.login(user)
    }

    private func unauthorized(_ error: any Error) -> Abort {
        // Point the client at the protected resource metadata document.
        var headers = HTTPFields()
        if let metadataURL = self.resourceServer.configuration.protectedResourceMetadataURL {
            headers[.wwwAuthenticate] = "Bearer resource_metadata=\"\(metadataURL.absoluteString)\""
        } else {
            headers[.wwwAuthenticate] = "Bearer"
        }
        return Abort(.unauthorized, headers: headers, reason: "\(error)")
    }

    private func insufficientScope(_ missing: Set<String>) -> Abort {
        // Advertise the missing scopes in the challenge.
        var headers = HTTPFields()
        let scope = missing.sorted().joined(separator: " ")
        headers[.wwwAuthenticate] = "Bearer error=\"insufficient_scope\", scope=\"\(scope)\""
        return Abort(.forbidden, headers: headers, reason: "Missing scope: \(scope)")
    }
}
