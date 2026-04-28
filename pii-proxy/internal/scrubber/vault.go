package scrubber

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Scope struct {
	OrgID          string
	WorkspaceID    string
	ConversationID string
	UserID         string
}

func (s Scope) Key() string {
	return strings.Join([]string{s.OrgID, s.WorkspaceID, s.ConversationID}, "\x00")
}

type Vault interface {
	GetOrCreate(ctx context.Context, scope Scope, entity EntityType, original string, next func() string) (string, error)
	RehydrateText(ctx context.Context, scope Scope, text string) (string, error)
}

type AuditEvent struct {
	RequestID     string
	UpstreamModel string
	Findings      map[string]int
	Denied        bool
	StatusCode    int
}

type AuditRecorder interface {
	RecordAuditEvent(ctx context.Context, scope Scope, event AuditEvent) error
}

type MemoryVault struct {
	mu       sync.Mutex
	forward  map[string]string
	reverse  map[string]string
	counters map[string]int
}

func NewMemoryVault() *MemoryVault {
	return &MemoryVault{
		forward:  map[string]string{},
		reverse:  map[string]string{},
		counters: map[string]int{},
	}
}

func (v *MemoryVault) GetOrCreate(_ context.Context, scope Scope, entity EntityType, original string, _ func() string) (string, error) {
	if v == nil {
		return "", fmt.Errorf("nil memory vault")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	scopeKey := scope.Key()
	forwardKey := strings.Join([]string{scopeKey, string(entity), original}, "\x00")
	if existing, ok := v.forward[forwardKey]; ok {
		return existing, nil
	}

	counterKey := strings.Join([]string{scopeKey, string(entity)}, "\x00")
	v.counters[counterKey]++
	surrogate := fmt.Sprintf("[%s_%d]", entity, v.counters[counterKey])
	v.forward[forwardKey] = surrogate
	v.reverse[strings.Join([]string{scopeKey, surrogate}, "\x00")] = original
	return surrogate, nil
}

func (v *MemoryVault) RehydrateText(_ context.Context, scope Scope, text string) (string, error) {
	if v == nil || text == "" {
		return text, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	scopePrefix := scope.Key() + "\x00"
	type mapping struct {
		surrogate string
		original  string
	}
	mappings := []mapping{}
	for key, original := range v.reverse {
		if strings.HasPrefix(key, scopePrefix) {
			mappings = append(mappings, mapping{surrogate: strings.TrimPrefix(key, scopePrefix), original: original})
		}
	}
	sort.Slice(mappings, func(i, j int) bool {
		return len(mappings[i].surrogate) > len(mappings[j].surrogate)
	})

	out := text
	for _, m := range mappings {
		out = strings.ReplaceAll(out, m.surrogate, m.original)
	}
	return out, nil
}
