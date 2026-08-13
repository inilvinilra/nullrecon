package httpapi

import (
	"net/http"
	"sort"
	"time"

	"github.com/nullrecon/nullrecon/reporting/renderer"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": s.now().Format(time.RFC3339)})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.db.Projects().List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects, "count": len(projects)})
}

func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	project, err := s.db.Projects().BySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	projectID, ok := s.project(r.Context(), w, r.PathValue("slug"))
	if !ok {
		return
	}
	findings, err := s.db.Findings().List(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "count": len(findings)})
}

func (s *Server) handleExposures(w http.ResponseWriter, r *http.Request) {
	projectID, ok := s.project(r.Context(), w, r.PathValue("slug"))
	if !ok {
		return
	}
	exposures, err := s.db.Exposures().ForProject(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exposures": exposures, "count": len(exposures)})
}

func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	projectID, ok := s.project(r.Context(), w, r.PathValue("slug"))
	if !ok {
		return
	}
	vulns, err := s.db.VulnCandidates().ForProject(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kev := 0
	for _, v := range vulns {
		if v.KEV {
			kev++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "count": len(vulns), "kev": kev})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	project, err := s.db.Projects().BySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	findings, err := s.db.Findings().List(r.Context(), project.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	exposures, _ := s.db.Exposures().ForProject(r.Context(), project.ID)
	secrets, _ := s.db.SecretCandidates().ForProject(r.Context(), project.ID)
	vulns, _ := s.db.VulnCandidates().ForProject(r.Context(), project.ID)
	data := renderer.New(project.ID, project.Slug, s.now())
	data.Findings = findings
	data.ExposureCount = len(exposures)
	data.VulnerabilityCount = len(vulns)
	for _, v := range vulns {
		if v.KEV {
			data.KEVCount++
		}
	}
	summary := map[string]int{}
	for _, sec := range secrets {
		summary[sec.Detector]++
	}
	data.SecretSummary = summary
	switch r.URL.Query().Get("format") {
	case "markdown", "md":
		body, err := renderer.RenderMarkdown(data)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write(body)
	case "sarif":
		body, err := renderer.RenderSARIF(data)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Write(body)
	default:
		writeJSON(w, http.StatusOK, data)
	}
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
		AuthRequired bool     `json:"authRequired"`
		Endpoint     string   `json:"endpoint"`
	}
	var entries []entry
	if s.registry != nil {
		for _, d := range s.registry.Descriptors() {
			caps := make([]string, 0, len(d.Capabilities))
			for _, c := range d.Capabilities {
				caps = append(caps, string(c))
			}
			sort.Strings(caps)
			entries = append(entries, entry{Name: d.Name, Capabilities: caps, AuthRequired: d.Auth.Required, Endpoint: d.Endpoint})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"services": entries, "count": len(entries)})
}

func (s *Server) handleCVEStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.CVEKnowledge().Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
