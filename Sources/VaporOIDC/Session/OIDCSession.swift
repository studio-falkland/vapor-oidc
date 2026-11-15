#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Vapor
import VaporOIDCCore

/// The session keys used by the OIDC adapter.
public struct OIDCSessionKeys: Sendable {
    /// The key that stores the `OIDCSubject`.
    public var subject: String

    /// The key that stores the ID token for RP-initiated logout.
    public var idToken: String

    /// Creates session keys.
    public init(
        subject: String = "_oidc_subject",
        idToken: String = "_oidc_id_token"
    ) {
        self.subject = subject
        self.idToken = idToken
    }
}

/// Reads and writes the OIDC login state in a Vapor session.
public struct OIDCSession: Sendable {
    /// The session keys.
    public var keys: OIDCSessionKeys

    /// Creates a session helper.
    public init(keys: OIDCSessionKeys = .init()) {
        self.keys = keys
    }

    /// Returns the stored subject.
    public func subject(for request: Request) -> OIDCSubject? {
        // Read the JSON value and decode the stable subject.
        guard let json = request.session.data[self.keys.subject],
              let data = json.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode(OIDCSubject.self, from: data)
    }

    /// Stores the subject and, optionally, the ID token.
    public func store(subject: OIDCSubject, idToken: String?, for request: Request) {
        // Encode the subject as JSON and store it.
        if let data = try? JSONEncoder().encode(subject),
           let json = String(data: data, encoding: .utf8) {
            request.session.data[self.keys.subject] = json
        }

        // Store the ID token only when the caller supplied one.
        request.session.data[self.keys.idToken] = idToken
    }

    /// Returns the stored ID token.
    public func idToken(for request: Request) -> String? {
        request.session.data[self.keys.idToken]
    }

    /// Clears the OIDC session data.
    public func clear(for request: Request) {
        // Remove both OIDC session values.
        request.session.data[self.keys.subject] = nil
        request.session.data[self.keys.idToken] = nil
    }
}
