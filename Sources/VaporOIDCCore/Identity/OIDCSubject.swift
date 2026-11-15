/// The stable identity of a user at a provider.
///
/// The combination of `issuer` and `subject` is the only identifier an OIDC
/// client can rely on across sessions. Email, phone, and username are not
/// stable identifiers.
public struct OIDCSubject: Hashable, Codable, Sendable {
    /// The issuer identifier.
    public let issuer: String

    /// The subject identifier.
    public let subject: String

    /// Creates a subject.
    public init(issuer: String, subject: String) {
        self.issuer = issuer
        self.subject = subject
    }
}
