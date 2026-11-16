#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import ExtrasBase64

extension Data {
    /// Returns a base64url-encoded string without padding.
    func base64URLEncodedString() -> String {
        Base64.encodeToString(
            bytes: self,
            options: [.base64UrlAlphabet, .omitPaddingCharacter]
        )
    }

    /// Creates data from a base64url-encoded string.
    init?(base64URLEncoded string: String) {
        guard let bytes = try? Base64.decode(
            string: string,
            options: [.base64UrlAlphabet, .omitPaddingCharacter]
        ) else {
            return nil
        }
        self.init(bytes)
    }
}
