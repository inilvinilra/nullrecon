package service

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type Service struct {
	contracts.Versioned
	ID         string            `json:"id"`
	ProjectID  string            `json:"projectId"`
	AssetID    string            `json:"assetId"`
	Protocol   string            `json:"protocol"`
	Port       int               `json:"port"`
	Name       string            `json:"name,omitempty"`
	BannerHash string            `json:"bannerHash,omitempty"`
	Source     string            `json:"source"`
	RawRef     string            `json:"rawRef,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	ObservedAt time.Time         `json:"observedAt"`
}

func New(projectID, assetID, protocol string, port int, source string, observed time.Time) Service {
	return Service{
		Versioned:  contracts.NewVersioned("service"),
		ID:         contracts.NewID("svc"),
		ProjectID:  projectID,
		AssetID:    assetID,
		Protocol:   protocol,
		Port:       port,
		Source:     source,
		ObservedAt: observed.UTC(),
	}
}
