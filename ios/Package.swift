// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "CavadVPN",
    platforms: [.iOS(.v16), .macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CavadVPNCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .target(
            name: "CavadVPNTransport",
            dependencies: ["CavadVPNCrypto"]
        ),
        .target(
            name: "CavadVPNClient",
            dependencies: ["CavadVPNCrypto", "CavadVPNTransport"]
        ),
        .testTarget(
            name: "CavadVPNCryptoTests",
            dependencies: ["CavadVPNCrypto"]
        ),
        .testTarget(
            name: "CavadVPNTransportTests",
            dependencies: ["CavadVPNTransport"]
        ),
        .testTarget(
            name: "CavadVPNClientTests",
            dependencies: ["CavadVPNClient"]
        ),
    ]
)
