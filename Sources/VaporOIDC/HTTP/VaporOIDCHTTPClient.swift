#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import HTTPTypes
import Vapor
import VaporOIDCCore

/// An ``OIDCHTTPClient`` backed by Vapor's application client.
public struct VaporOIDCHTTPClient: OIDCHTTPClient {
    private let client: any Client

    /// Creates a client.
    public init(client: any Client) {
        self.client = client
    }

    public func send(_ request: OIDCHTTPRequest) async throws -> OIDCHTTPResponse {
        // Convert the core headers into HTTPTypes fields.
        var headers = HTTPFields()
        for (name, value) in request.headers {
            if let fieldName = HTTPField.Name(name) {
                headers[fieldName] = value
            }
        }

        // Build and send the Vapor client request.
        let clientRequest = ClientRequest(
            method: HTTPRequest.Method(request.method) ?? .get,
            url: URI(string: request.url.absoluteString),
            headers: headers,
            body: request.body.map { .init(data: $0) } ?? .empty
        )
        let response = try await self.client.send(clientRequest)

        // Collect the response body.
        var body = response.body
        let data = try await body.collect() ?? Data()

        // Convert the response headers back into a plain dictionary.
        var responseHeaders: [String: String] = [:]
        for field in response.headers {
            responseHeaders[field.name.canonicalName] = field.value
        }

        return OIDCHTTPResponse(
            statusCode: Int(response.status.code),
            headers: responseHeaders,
            body: data
        )
    }
}
