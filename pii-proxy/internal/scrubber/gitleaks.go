package scrubber

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gldetect "github.com/zricethezav/gitleaks/v8/detect"
)

type GitleaksDetector struct {
	mu       sync.Mutex
	detector *gldetect.Detector
}

func NewGitleaksDetector() (*GitleaksDetector, error) {
	detector, err := gldetect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	return &GitleaksDetector{detector: detector}, nil
}

func (d *GitleaksDetector) Find(ctx context.Context, text string) ([]Finding, error) {
	if d == nil || d.detector == nil || text == "" {
		return nil, nil
	}

	d.mu.Lock()
	findings := d.detector.DetectContext(ctx, gldetect.Fragment{Raw: text})
	d.mu.Unlock()

	out := make([]Finding, 0, len(findings))
	seen := map[string]struct{}{}
	for _, finding := range findings {
		for _, value := range gitleaksValues(text, finding.Secret, finding.Match) {
			start := 0
			for {
				idx := strings.Index(text[start:], value)
				if idx < 0 {
					break
				}
				absStart := start + idx
				absEnd := absStart + len(value)
				key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", EntitySecret, value, absStart, absEnd)
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					out = append(out, Finding{
						Type:  EntitySecret,
						Start: absStart,
						End:   absEnd,
						Value: value,
					})
				}
				start = absEnd
			}
		}
	}
	return out, nil
}

func gitleaksValues(text, secret, match string) []string {
	values := []string{}
	secret = strings.TrimSpace(secret)
	match = strings.TrimSpace(match)
	if secret != "" && strings.Contains(text, secret) {
		values = append(values, secret)
	}
	if len(values) == 0 && match != "" && strings.Contains(text, match) {
		values = append(values, match)
	}
	return values
}
