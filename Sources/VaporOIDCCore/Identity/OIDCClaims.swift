#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A set of OIDC claims.
public struct OIDCClaims: Codable, Sendable, Equatable {
    /// The raw claim values.
    public var values: [String: OIDCClaimValue]

    /// Creates a claim set.
    public init(_ values: [String: OIDCClaimValue] = [:]) {
        self.values = values
    }

    /// Reads or writes a claim.
    public subscript(_ name: String) -> OIDCClaimValue? {
        get { self.values[name] }
        set { self.values[name] = newValue }
    }

    /// Returns a string claim.
    public func string(_ name: String) -> String? {
        guard case .string(let value)? = self.values[name] else { return nil }
        return value
    }

    /// Returns a boolean claim.
    public func bool(_ name: String) -> Bool? {
        guard case .bool(let value)? = self.values[name] else { return nil }
        return value
    }

    /// Returns a numeric claim.
    public func number(_ name: String) -> Double? {
        guard case .number(let value)? = self.values[name] else { return nil }
        return value
    }

    /// Returns an array claim.
    public func array(_ name: String) -> [OIDCClaimValue]? {
        guard case .array(let value)? = self.values[name] else { return nil }
        return value
    }

    /// Returns an object claim.
    public func object(_ name: String) -> [String: OIDCClaimValue]? {
        guard case .object(let value)? = self.values[name] else { return nil }
        return value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.values = try container.decode([String: OIDCClaimValue].self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.values)
    }
}
