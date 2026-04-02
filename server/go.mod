module github.com/cavad93/vpn/server

go 1.24.7

require golang.org/x/crypto v0.32.0

require (
	golang.org/x/sys v0.29.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Windows-only: Wintun kernel TUN driver (Go bindings).
// wintun.dll must be present in the same directory as the server binary.
// Download from https://www.wintun.net/ or let install_server.ps1 do it.
require golang.zx2c4.com/wintun v0.0.0-20230126332819-7c9e2f794d6c
