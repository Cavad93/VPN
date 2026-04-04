package api

import (
	"encoding/json"
	"net/http"
)

// VLESSInfo holds the VLESS connection info returned by the API.
type VLESSInfo struct {
	Link string `json:"link"`
	UUID string `json:"uuid"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
}

// vlessInfo stores the VLESS link info set by the main server.
// Protected by the APIServer mux (single writer at startup).
var vlessInfoData *VLESSInfo

// SetVLESSInfo registers the VLESS connection info and the API endpoint.
func (a *APIServer) SetVLESSInfo(info VLESSInfo) {
	vlessInfoData = &info
	a.mux.HandleFunc("GET /api/v1/vless/link", a.auth(a.handleVLESSLink))
}

func (a *APIServer) handleVLESSLink(w http.ResponseWriter, r *http.Request) {
	if vlessInfoData == nil {
		http.Error(w, `{"error":"VLESS not configured"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vlessInfoData)
}
