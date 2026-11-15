#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A test double for ``OIDCHTTPClient``.
public actor MockOIDCHTTPClient: OIDCHTTPClient {
    /// The requests sent through the client.
    public private(set) var requests: [OIDCHTTPRequest] = []

    private var responses: [URL: OIDCHTTPResponse] = [:]
    private var error: OIDCError?

    /// Creates a mock client.
    public init() {}

    /// Registers a response for a URL.
    public func setResponse(_ response: OIDCHTTPResponse, for url: URL) {
        self.responses[url] = response
    }

    /// Makes every request throw the supplied error.
    public func setError(_ error: OIDCError) {
        self.error = error
    }

    public func send(_ request: OIDCHTTPRequest) async throws -> OIDCHTTPResponse {
        // Record the request for assertions.
        self.requests.append(request)

        // Throw the configured error, if any.
        if let error {
            throw error
        }

        // Return the registered response, or a 404.
        guard let response = self.responses[request.url] else {
            return OIDCHTTPResponse(statusCode: 404, body: Data())
        }
        return response
    }
}
