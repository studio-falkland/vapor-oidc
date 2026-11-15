import Testing
@testable import VaporOIDC

@Suite("OIDCOptions")
struct OIDCOptionsTests {
    @Test
    func allowsRelativeRedirects() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("/dashboard") == "/dashboard")
        #expect(options.sanitizeRedirect("//evil.example") == "/")
        #expect(options.sanitizeRedirect("https://evil.example") == "/")
    }

    @Test
    func allowsConfiguredOrigins() {
        let options = OIDCOptions(
            allowedRedirectOrigins: ["https://app.example"]
        )
        #expect(
            options.sanitizeRedirect("https://app.example/dashboard")
                == "https://app.example/dashboard"
        )
        #expect(
            options.sanitizeRedirect("https://evil.example/dashboard")
                == "/"
        )
    }
}
