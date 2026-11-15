import Vapor
import VaporOIDCCore

/// Stores the per-login state between the authorization request and callback.
public protocol OIDCStateStore: Sendable {
    /// Saves a state value.
    func save(_ state: OIDCState, for request: Request) throws

    /// Consumes a state value, removing it from the store.
    func consume(state: String, for request: Request) throws -> OIDCState?
}
