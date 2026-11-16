#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Vapor

/// Shared form encoding and client authentication for token requests.
enum OIDCFormRequest {
    /// Form-encodes a request body.
    static func encode(_ body: [String: String]) throws -> Data {
        let encoded = try URLEncodedFormEncoder().encode(body)
        return Data(encoded.utf8)
    }

    /// Applies the configured client authentication method.
    static func applyClientAuthentication(
        headers: inout [String: String],
        body: inout [String: String],
        clientID: String,
        clientSecret: String?,
        method: OIDCTokenEndpointAuthenticationMethod
    ) throws {
        switch method {
        case .clientSecretBasic:
            guard let clientSecret else {
                throw OIDCError.missingClientSecret
            }
            let credentials = "\(clientID):\(clientSecret)"
            headers["Authorization"] = "Basic \(Data(credentials.utf8).base64EncodedString())"
        case .clientSecretPost:
            if let clientSecret {
                body["client_secret"] = clientSecret
            }
        case .none:
            break
        }
    }
}
