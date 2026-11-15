#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The response from an RFC 7662 introspection endpoint.
struct OIDCIntrospectionResponse: Codable, Sendable {
    let active: Bool
    let scope: String?
    let scp: [String]?
    let clientID: String?
    let username: String?
    let tokenType: String?
    let exp: Int?
    let iat: Int?
    let nbf: Int?
    let sub: String?
    let aud: AudienceValue?
    let iss: String?
    let jti: String?

    enum CodingKeys: String, CodingKey {
        case active
        case scope
        case scp
        case clientID = "client_id"
        case username
        case tokenType = "token_type"
        case exp
        case iat
        case nbf
        case sub
        case aud
        case iss
        case jti
    }

    enum AudienceValue: Codable, Sendable {
        case string(String)
        case array([String])

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let value = try? container.decode(String.self) {
                self = .string(value)
            } else {
                self = .array(try container.decode([String].self))
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value):
                try container.encode(value)
            case .array(let value):
                try container.encode(value)
            }
        }

        var values: [String] {
            switch self {
            case .string(let value):
                return [value]
            case .array(let value):
                return value
            }
        }
    }
}
