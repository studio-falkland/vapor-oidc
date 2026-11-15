// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "vapor-oidc",
    platforms: [
        .macOS("26.2"),
    ],
    products: [
        .library(name: "VaporOIDC", targets: ["VaporOIDC"]),
        .library(name: "VaporOIDCCore", targets: ["VaporOIDCCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "5.0.0-beta.4"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.14.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-http-types.git", from: "1.7.0"),
    ],
    targets: [
        .target(
            name: "VaporOIDCCore",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "VaporOIDC",
            dependencies: [
                "VaporOIDCCore",
                .product(name: "Vapor", package: "vapor"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .testTarget(
            name: "VaporOIDCCoreTests",
            dependencies: ["VaporOIDCCore"]
        ),
        .testTarget(
            name: "VaporOIDCTests",
            dependencies: [
                "VaporOIDC",
                .product(name: "Vapor", package: "vapor"),
                .product(name: "VaporTesting", package: "vapor"),
            ]
        ),
    ]
)
