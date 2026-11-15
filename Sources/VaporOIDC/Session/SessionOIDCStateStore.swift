#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Vapor
import VaporOIDCCore

/// Stores OIDC state values in the Vapor session.
///
/// The store keeps a JSON dictionary of in-flight states, so multiple tabs can
/// log in concurrently. Expired states are pruned on read.
public struct SessionOIDCStateStore: OIDCStateStore {
    /// The session key that stores the state dictionary.
    public var key: String

    /// How long a state remains valid.
    public var maximumAge: TimeInterval

    /// Creates a session-backed state store.
    public init(
        key: String = "_oidc_states",
        maximumAge: TimeInterval = 600
    ) {
        self.key = key
        self.maximumAge = maximumAge
    }

    public func save(_ state: OIDCState, for request: Request) throws {
        // Load the current states, add the new one, and write them back.
        var states = self.load(from: request)
        states[state.state] = state
        try self.store(states, on: request)
    }

    public func consume(state: String, for request: Request) throws -> OIDCState? {
        // Remove the matching state so it cannot be replayed.
        var states = self.load(from: request)
        let value = states.removeValue(forKey: state)
        try self.store(states, on: request)
        return value
    }

    private func load(from request: Request) -> [String: OIDCState] {
        // Decode the stored dictionary, or start empty.
        guard let json = request.session.data[self.key],
              let data = json.data(using: .utf8),
              let states = try? JSONDecoder().decode([String: OIDCState].self, from: data) else {
            return [:]
        }

        // Drop states older than the configured maximum age.
        let cutoff = Date().addingTimeInterval(-self.maximumAge)
        return states.filter { $0.value.createdAt > cutoff }
    }

    private func store(_ states: [String: OIDCState], on request: Request) throws {
        // Encode the dictionary and write it to the session.
        let data = try JSONEncoder().encode(states)
        request.session.data[self.key] = String(data: data, encoding: .utf8)
    }
}
