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

    @Test
    func storesAndReadsIDToken() async throws {
        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)

            app.get("set") { request in
                OIDCSession().store(
                    subject: OIDCSubject(
                        issuer: "https://issuer.example",
                        subject: "123"
                    ),
                    idToken: "id-token",
                    for: request
                )
                return "ok"
            }

            app.get("read") { request in
                OIDCSession().idToken(for: request) ?? "none"
            }

            try await app.testing { client in
                let set = try await client.get("set")
                let cookies = try #require(set.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let read = try await client.get("read", headers: headers)
                #expect(try await read.body.requireString() == "id-token")
            }
        }
    }

    @Test
    func clearsSubjectAndIDToken() async throws {
        try await withApp { app in
            app.middleware.use(app.sessionsMiddleware)

            app.get("set") { request in
                OIDCSession().store(
                    subject: OIDCSubject(
                        issuer: "https://issuer.example",
                        subject: "123"
                    ),
                    idToken: "id-token",
                    for: request
                )
                return "ok"
            }

            app.get("clear") { request in
                OIDCSession().clear(for: request)
                return "ok"
            }

            app.get("read") { request in
                let session = OIDCSession()
                let subject = session.subject(for: request)?.subject ?? "none"
                let token = session.idToken(for: request) ?? "none"
                return "\(subject):\(token)"
            }

            try await app.testing { client in
                let set = try await client.get("set")
                let cookies = try #require(set.headers.setCookie)
                let cookie = try #require(cookies["vapor-session"])

                var headers = HTTPFields()
                headers[.cookie] = "vapor-session=\(cookie.string)"
                let clear = try await client.get("clear", headers: headers)
                #expect(clear.status == .ok)

                if let clearCookie = clear.headers.setCookie?["vapor-session"]?.string {
                    headers[.cookie] = "vapor-session=\(clearCookie)"
                }
                let read = try await client.get("read", headers: headers)
                #expect(try await read.body.requireString() == "none:none")
            }
        }
    }
}
