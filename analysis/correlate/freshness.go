package correlate

import (
	"math"
	"time"
)

var halfLifeByClass = map[string]time.Duration{
	"hourly":  24 * time.Hour,
	"daily":   7 * 24 * time.Hour,
	"weekly":  30 * 24 * time.Hour,
	"static":  0,
	"unknown": 14 * 24 * time.Hour,
}

func FreshnessScore(class string, observedAt, now time.Time) float64 {
	halfLife, ok := halfLifeByClass[class]
	if !ok {
		halfLife = halfLifeByClass["unknown"]
	}
	if halfLife == 0 {
		return 1
	}
	if observedAt.IsZero() {
		return 0.1
	}
	age := now.UTC().Sub(observedAt.UTC())
	if age < 0 {
		age = 0
	}
	return math.Pow(2, -float64(age)/float64(halfLife))
}

func FreshnessLabel(class string, observedAt, now time.Time) string {
	score := FreshnessScore(class, observedAt, now)
	switch {
	case score >= 0.75:
		return "current"
	case score >= 0.25:
		return "aging"
	default:
		return "historical"
	}
}
