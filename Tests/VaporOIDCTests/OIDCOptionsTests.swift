import Testing
@testable import VaporOIDC

@Suite("OIDCOptions")
struct OIDCOptionsTests {
    @Test
    func allowsRelativeRedirects() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("/dashboard") == "/dashboard")
        #expect(options.sanitizeRedirect("/a/b?x=1#y") == "/a/b?x=1#y")
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

    @Test
    func fallsBackForMissingOrEmptyValues() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect(nil) == "/")
        #expect(options.sanitizeRedirect("") == "/")
        #expect(options.sanitizeRedirect(" ") == "/")
    }

    @Test
    func usesConfiguredDefault() {
        let options = OIDCOptions(defaultRedirectAfterLogin: "/home")
        #expect(options.sanitizeRedirect(nil) == "/home")
        #expect(options.sanitizeRedirect("https://evil.example") == "/home")
    }

    @Test
    func rejectsProtocolRelativeRedirects() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("//evil.example") == "/")
        #expect(options.sanitizeRedirect("///evil.example") == "/")
    }

    @Test
    func rejectsBackslashAfterLeadingSlash() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("/\\evil.example") == "/")
    }

    @Test
    func rejectsControlCharactersAfterLeadingSlash() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("/\t/evil.example") == "/")
        #expect(options.sanitizeRedirect("/\n/evil.example") == "/")
        #expect(options.sanitizeRedirect("/\r/evil.example") == "/")
        #expect(options.sanitizeRedirect("/\u{0000}/evil.example") == "/")
        #expect(options.sanitizeRedirect("/\u{007F}/evil.example") == "/")
    }

    @Test
    func rejectsUnsafeCharactersInAbsoluteURLs() {
        let options = OIDCOptions(
            allowedRedirectOrigins: ["https://app.example"]
        )
        #expect(options.sanitizeRedirect("https://app.example/a\\b") == "/")
        #expect(
            options.sanitizeRedirect("https://app.example/\t/evil.example")
                == "/"
        )
    }

    @Test
    func rejectsAbsoluteURLsWithUntrustedUserInfo() {
        let options = OIDCOptions(
            allowedRedirectOrigins: ["https://app.example"]
        )
        #expect(
            options.sanitizeRedirect("https://app.example@evil.example/")
                == "/"
        )
        #expect(
            options.sanitizeRedirect("https://app.example.evil.example/")
                == "/"
        )
    }

    @Test
    func rejectsUnsupportedSchemes() {
        let options = OIDCOptions()
        #expect(options.sanitizeRedirect("javascript:alert(1)") == "/")
        #expect(options.sanitizeRedirect("data:text/html,hello") == "/")
        #expect(options.sanitizeRedirect("ftp://app.example/file") == "/")
    }
}
