//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func configDir() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "", fmt.Errorf("config: APPDATA environment variable not set")
	}
	return filepath.Join(appData, "CavadVPN"), nil
}
