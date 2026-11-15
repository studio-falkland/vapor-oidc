#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The JOSE header of a JWT.
struct OIDCJWTHeader: Decodable {
    let alg: String
    let kid: String?
    let x5u: String?
    let x5c: [String]?
    let jku: String?
    let jwk: OIDCClaimValue?

    /// Decodes the header from a compact JWT.
    static func decode(_ token: String) throws -> OIDCJWTHeader {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw OIDCError.invalidTokenHeader("Malformed JWT.")
        }
        guard let data = Data(base64URLEncoded: String(parts[0])) else {
            throw OIDCError.invalidTokenHeader("Malformed JWT header.")
        }
        do {
            return try JSONDecoder().decode(OIDCJWTHeader.self, from: data)
        } catch {
            throw OIDCError.invalidTokenHeader("Unable to decode the JWT header: \(error)")
        }
    }

    /// Rejects unsafe algorithms and key references.
    func validate(allowedAlgorithms: Set<String>) throws {
        let algorithm = self.alg.lowercased()
        guard algorithm != "none", !algorithm.hasPrefix("hs") else {
            throw OIDCError.unsupportedAlgorithm(self.alg)
        }
        guard allowedAlgorithms.contains(self.alg) else {
            throw OIDCError.unsupportedAlgorithm(self.alg)
        }
        guard self.x5u == nil, self.x5c == nil, self.jku == nil, self.jwk == nil else {
            throw OIDCError.invalidTokenHeader("Unsupported JOSE header parameters.")
        }
    }
}
