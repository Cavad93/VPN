module github.com/cavad93/vpn/server

go 1.24.7

require golang.org/x/crypto v0.32.0

require (
	golang.org/x/sys v0.29.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Windows-only: Wintun kernel TUN driver (Go bindings).
// wintun.dll must be present in the same directory as the server binary.
// Run "go get golang.zx2c4.com/wintun@latest" before building on Windows.
