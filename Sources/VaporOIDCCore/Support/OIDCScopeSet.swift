/// Parses scopes from the `scope` string and `scp` array forms.
enum OIDCScopeSet {
    static func parse(scope: String?, scp: [String]?) -> Set<String> {
        var scopes = Set<String>()
        if let scope {
            scopes.formUnion(scope.split(separator: " ").map(String.init))
        }
        if let scp {
            scopes.formUnion(scp)
        }
        return scopes
    }
}
