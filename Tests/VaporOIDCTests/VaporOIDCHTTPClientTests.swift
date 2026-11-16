#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import HTTPTypes
import Testing
import Vapor
@testable import VaporOIDC
@testable import VaporOIDCCore

private struct StubClient: Client {
    let contentConfiguration: ContentConfiguration = .default()
    let response: ClientResponse
    let recorder: RequestRecorder

    func send(_ request: ClientRequest) async throws -> ClientResponse {
        await self.recorder.record(request)
        return self.response
    }
}

private actor RequestRecorder {
    private(set) var requests: [ClientRequest] = []

    func record(_ request: ClientRequest) {
        self.requests.append(request)
    }
}

@Suite("VaporOIDCHTTPClient")
struct VaporOIDCHTTPClientTests {
    @Test
    func sendsRequestAndCollectsResponse() async throws {
        let recorder = RequestRecorder()
        var responseHeaders = HTTPFields()
        responseHeaders[.contentType] = "application/json"
        let response = ClientResponse(
            status: .ok,
            headers: responseHeaders,
            body: .init(data: Data(#"{"ok":true}"#.utf8))
        )
        let client = VaporOIDCHTTPClient(
            client: StubClient(response: response, recorder: recorder)
        )

        let result = try await client.send(
            OIDCHTTPRequest(
                method: "POST",
                url: URL(string: "https://issuer.example/token")!,
                headers: ["Content-Type": "application/x-www-form-urlencoded"],
                body: Data("grant_type=authorization_code".utf8)
            )
        )

        #expect(result.statusCode == 200)
        #expect(String(decoding: result.body, as: UTF8.self) == #"{"ok":true}"#)

        let requests = await recorder.requests
        #expect(requests.count == 1)
        #expect(requests.first?.method == .post)
        #expect(requests.first?.url.string == "https://issuer.example/token")
        #expect(
            requests.first?.headers[.contentType]
                == "application/x-www-form-urlencoded"
        )
        #expect(requests.first?.headers[.acceptEncoding] == "identity")
    }

    @Test
    func preservesCallerSuppliedAcceptEncoding() async throws {
        let recorder = RequestRecorder()
        let response = ClientResponse(status: .ok, body: .init(data: Data()))
        let client = VaporOIDCHTTPClient(
            client: StubClient(response: response, recorder: recorder)
        )

        _ = try await client.send(
            OIDCHTTPRequest(
                method: "GET",
                url: URL(string: "https://issuer.example/jwks")!,
                headers: ["Accept-Encoding": "gzip"]
            )
        )

        let requests = await recorder.requests
        #expect(requests.first?.headers[.acceptEncoding] == "gzip")
    }
}
