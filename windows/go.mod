module github.com/cavad93/vpn/windows

go 1.24.7

require (
	github.com/cavad93/vpn/server v0.0.0
	golang.org/x/sys v0.29.0
)

require golang.org/x/crypto v0.32.0 // indirect

replace github.com/cavad93/vpn/server => ../server
