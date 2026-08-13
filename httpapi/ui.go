package httpapi

import (
	_ "embed"
	"net/http"
)

//go:embed ui.html
var uiPage []byte

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiPage)
}
