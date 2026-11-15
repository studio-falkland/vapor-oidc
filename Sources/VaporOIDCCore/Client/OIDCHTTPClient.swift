#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An HTTP request sent by the OIDC client.
public struct OIDCHTTPRequest: Sendable {
    /// The HTTP method.
    public var method: String

    /// The request URL.
    public var url: URL

    /// The request headers.
    public var headers: [String: String]

    /// The request body.
    public var body: Data?

    /// Creates a request.
    public init(
        method: String,
        url: URL,
        headers: [String: String] = [:],
        body: Data? = nil
    ) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

/// An HTTP response received by the OIDC client.
public struct OIDCHTTPResponse: Sendable {
    /// The HTTP status code.
    public var statusCode: Int

    /// The response headers.
    public var headers: [String: String]

    /// The response body.
    public var body: Data

    /// Creates a response.
    public init(
        statusCode: Int,
        headers: [String: String] = [:],
        body: Data
    ) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }
}

/// The HTTP transport used by the OIDC client.
public protocol OIDCHTTPClient: Sendable {
    /// Sends a request and returns the response.
    func send(_ request: OIDCHTTPRequest) async throws -> OIDCHTTPResponse
}
