import HTTPTypes
import Testing
import Vapor
import VaporTesting
@testable import VaporOIDC
@testable import VaporOIDCCore

@Suite("OIDCSession")
struct OIDCSessionTests {
    @Test
    func storesAndReadsSubject() async throws {
        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)

            app.get("set") { request in
                let session = OIDCSession()
                session.store(
                    subject: OIDCSubject(
                        issuer: "https://issuer.example",
                        subject: "123"
                    ),
                    idToken: "token",
                    for: request
                )
                return "ok"
            }

            app.get("read") { request in
                let session = OIDCSession()
                return session.subject(for: request)?.subject ?? "none"
            }

            try await app.testing { client in
                let set = try await client.get("set")
                #expect(set.status == .ok)
                let cookies = try #require(set.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let read = try await client.get("read", headers: headers)
                #expect(try await read.body.requireString() == "123")
            }
        }
    }
}
