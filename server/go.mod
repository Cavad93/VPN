module github.com/cavad93/vpn/server

go 1.24.7

require (
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.32.0
	golang.org/x/sys v0.29.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gopkg.in/yaml.v3 v3.0.1
)

// Windows-only: Wintun kernel TUN driver (Go bindings).
// wintun.dll must be present in the same directory as the server binary.
// Run "go get golang.zx2c4.com/wintun@latest" before building on Windows.
