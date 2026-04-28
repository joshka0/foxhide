package scrubber

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestScrubTextRedactsCommonEntities(t *testing.T) {
	sc := New()
	input := `My name is Sarah Kim. Email sarah.kim@acme.com or phone (415) 555-1212. SSN 123-45-6789. Card 4111 1111 1111 1111. api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456. dob: 1980-02-03. Claim number CLM-88317.`
	out := sc.ScrubText(input)
	for _, s := range []string{"Sarah Kim", "sarah.kim@acme.com", "(415) 555-1212", "123-45-6789", "4111 1111 1111 1111", "sk-proj-abcdefghijklmnopqrstuvwxyz123456", "1980-02-03", "CLM-88317"} {
		if strings.Contains(out, s) {
			t.Fatalf("expected %q to be redacted; output=%s", s, out)
		}
	}
	for _, s := range []string{"[PERSON_1]", "[EMAIL_1]", "[PHONE_1]", "[SSN_1]", "[CREDIT_CARD_1]", "[SECRET_1]", "[DOB_1]", "[ID_1]"} {
		if !strings.Contains(out, s) {
			t.Fatalf("expected placeholder %q; output=%s", s, out)
		}
	}
}

func TestRepeatedValueGetsStablePlaceholder(t *testing.T) {
	sc := New()
	out := sc.ScrubText(`Email ann@example.com, then ann@example.com again.`)
	if strings.Count(out, "[EMAIL_1]") != 2 {
		t.Fatalf("expected repeated email to use stable placeholder; output=%s", out)
	}
}

func TestScrubPayloadScrubsJSONStringValues(t *testing.T) {
	sc := New()
	body := []byte(`{"messages":[{"role":"user","content":"Email bob@example.com and call 555-0102."}],"temperature":0}`)
	out := ScrubPayload(body, "application/json", sc)
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("expected valid JSON after scrubbing: %v; body=%s", err, string(out))
	}
	content := decoded["messages"].([]any)[0].(map[string]any)["content"].(string)
	if strings.Contains(content, "bob@example.com") || strings.Contains(content, "555-0102") {
		t.Fatalf("expected content scrubbed; content=%s", content)
	}
}

func TestScrubPayloadDoesNotTruncateJSONL(t *testing.T) {
	body := []byte("{\"content\":\"Email ann@example.com\"}\n{\"content\":\"Email bob@example.com\"}\n")
	out := ScrubPayloadWithPolicy(body, "", New(), DefaultPayloadPolicy())
	if strings.Contains(string(out), "ann@example.com") || strings.Contains(string(out), "bob@example.com") {
		t.Fatalf("expected JSONL content scrubbed; body=%s", string(out))
	}
	if strings.Count(string(out), "\n") != 2 {
		t.Fatalf("expected JSONL line structure preserved; body=%q", string(out))
	}
	if !strings.Contains(string(out), "[EMAIL_1]") || !strings.Contains(string(out), "[EMAIL_2]") {
		t.Fatalf("expected both JSONL records preserved and scrubbed; body=%s", string(out))
	}
}

func TestSchemaModeOnlyScrubsIncludedPathsAndSensitiveKeys(t *testing.T) {
	policy := DefaultPayloadPolicy()
	policy.JSONMode = JSONModeSchema
	body := []byte(`{"model":"call 415-555-1212","messages":[{"role":"user","content":"Email bob@example.com and call 415-555-1212"}],"notes":"Email should-not-scrub@example.com","api_key":"tiny-secret"}`)
	out := ScrubPayloadWithPolicy(body, "application/json", New(), policy)
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["model"].(string) != "call 415-555-1212" {
		t.Fatalf("schema mode should not scrub model; got %q", decoded["model"])
	}
	if decoded["notes"].(string) != "Email should-not-scrub@example.com" {
		t.Fatalf("schema mode should not scrub notes; got %q", decoded["notes"])
	}
	if strings.Contains(string(out), "bob@example.com") || strings.Contains(string(out), "tiny-secret") {
		t.Fatalf("expected included content and key secrets scrubbed; body=%s", string(out))
	}
}

func TestSensitiveJSONKeysScrubWholeValues(t *testing.T) {
	out := ScrubPayloadWithPolicy([]byte(`{"password":"short","contact_email":"jane@example.com","account_id":"acct-12345"}`), "application/json", New(), DefaultPayloadPolicy())
	for _, forbidden := range []string{"short", "jane@example.com", "acct-12345"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("expected %q scrubbed; body=%s", forbidden, string(out))
		}
	}
}

func TestRehydratePayloadUsesRequestPlaceholderSnapshot(t *testing.T) {
	sc := New()
	_ = ScrubPayload([]byte(`{"messages":[{"content":"Email ann@example.com"}]}`), "application/json", sc)
	out := RehydratePayload([]byte(`{"choices":[{"message":{"content":"I will email [EMAIL_1]."}}]}`), "application/json", sc.PlaceholderMap())
	if !strings.Contains(string(out), "ann@example.com") {
		t.Fatalf("expected rehydrated email; body=%s", string(out))
	}
}

func TestScrubQueryValues(t *testing.T) {
	q := url.Values{"email": {"pat@example.com"}, "q": {"call 415-555-1212"}}
	out := ScrubQueryValues(q, New()).Encode()
	if strings.Contains(out, "pat%40example.com") || strings.Contains(out, "415-555-1212") {
		t.Fatalf("query was not scrubbed: %s", out)
	}
}

func TestIBANAndSecrets(t *testing.T) {
	out := New().ScrubText("IBAN GB82 WEST 1234 5698 7654 32 and token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD")
	if strings.Contains(out, "GB82 WEST") || strings.Contains(out, "ghp_") {
		t.Fatalf("expected IBAN and token scrubbed: %s", out)
	}
	if !strings.Contains(out, "[IBAN_1]") || !strings.Contains(out, "[SECRET_1]") {
		t.Fatalf("expected placeholders: %s", out)
	}
}

type stubDetector struct{}

func (stubDetector) Find(_ context.Context, text string) ([]Finding, error) {
	start := strings.Index(text, "Project Phoenix")
	if start < 0 {
		return nil, nil
	}
	return []Finding{{
		Type:  EntityModel,
		Start: start,
		End:   start + len("Project Phoenix"),
		Value: "Project Phoenix",
	}}, nil
}

func TestScrubTextUsesExternalDetector(t *testing.T) {
	sc := NewWithDetectors(stubDetector{})
	out := sc.ScrubText("Internal codename Project Phoenix should not leave.")
	if strings.Contains(out, "Project Phoenix") {
		t.Fatalf("expected external detector finding scrubbed: %s", out)
	}
	if !strings.Contains(out, "[MODEL_PRIVATE_1]") {
		t.Fatalf("expected model placeholder: %s", out)
	}
}

func TestScrubTextRedactsContextualProjectNames(t *testing.T) {
	out := New().ScrubText("Internal codename Project Phoenix should not leave.")
	if strings.Contains(out, "Project Phoenix") {
		t.Fatalf("expected contextual project name scrubbed: %s", out)
	}
	if !strings.Contains(out, "[MODEL_PRIVATE_1]") {
		t.Fatalf("expected model-private placeholder: %s", out)
	}
}

func TestTranscriptProfileReducesNumericFalsePositives(t *testing.T) {
	sc := NewWithProfile(ProfileTranscript)
	out := sc.ScrubText(`{"time":1772023902312,"resets_at":1772023902,"responseTime":16.1772023902312,"tmp":"go-link-123456789/thing","account deletion policy readiness":true}`)
	if strings.Contains(out, "[PHONE_") || strings.Contains(out, "[CREDIT_CARD_") || strings.Contains(out, "[SSN_") || strings.Contains(out, "[ID_") {
		t.Fatalf("expected transcript profile to ignore noisy numeric/log contexts; output=%s", out)
	}
}

func TestTranscriptProfileKeepsContextualPhoneAndCard(t *testing.T) {
	sc := NewWithProfile(ProfileTranscript)
	out := sc.ScrubText(`Call 415-555-1212. My card number is 4111 1111 1111 1111.`)
	if strings.Contains(out, "415-555-1212") || strings.Contains(out, "4111 1111 1111 1111") {
		t.Fatalf("expected contextual phone and card redacted; output=%s", out)
	}
	if !strings.Contains(out, "[PHONE_1]") || !strings.Contains(out, "[CREDIT_CARD_1]") {
		t.Fatalf("expected placeholders; output=%s", out)
	}
}

func TestTranscriptProfileScrubsURLBeforeEmailQuery(t *testing.T) {
	sc := NewWithProfile(ProfileTranscript)
	out := sc.ScrubText(`curl -s 'http://localhost:8080/v1/chat/completions?email=sarah.kim@example.com'`)
	if strings.Contains(out, "localhost:8080") || strings.Contains(out, "sarah.kim@example.com") {
		t.Fatalf("expected URL with query scrubbed as a unit; output=%s", out)
	}
	if !strings.Contains(out, "[URL_1]") {
		t.Fatalf("expected URL placeholder; output=%s", out)
	}
}

func TestTranscriptProfileSuppressesModelPrivate(t *testing.T) {
	sc := NewWithProfile(ProfileTranscript)
	out := sc.ScrubText(`Internal codename Project Phoenix appears in docs.`)
	if strings.Contains(out, "[MODEL_PRIVATE_") {
		t.Fatalf("expected transcript profile to suppress model-private detector; output=%s", out)
	}
}

func TestTranscriptProfileFiltersKeywordSecretFalsePositive(t *testing.T) {
	detector := stubSecretDetector{finding: Finding{Type: EntitySecret, Start: 10, End: 30, Value: "token-classification"}}
	sc := NewWithProfile(ProfileTranscript, detector)
	out := sc.ScrubText(`pipeline token-classification should stay`)
	if strings.Contains(out, "[SECRET_") {
		t.Fatalf("expected token-classification false positive filtered; output=%s", out)
	}
}

func TestTranscriptProfileKeepsRealExternalSecret(t *testing.T) {
	detector := stubSecretDetector{finding: Finding{Type: EntitySecret, Start: 8, End: 26, Value: "real-secret-value"}}
	sc := NewWithProfile(ProfileTranscript, detector)
	out := sc.ScrubText(`apiKey real-secret-value should scrub`)
	if strings.Contains(out, "real-secret-value") || !strings.Contains(out, "[SECRET_1]") {
		t.Fatalf("expected external secret kept; output=%s", out)
	}
}

func TestMemoryVaultStableAcrossRequests(t *testing.T) {
	vault := NewMemoryVault()
	scope := Scope{OrgID: "foxway", WorkspaceID: "security", ConversationID: "case-1", UserID: "josh@example.com"}

	first := NewScoped(scope, vault).ScrubText("Email ann@example.com")
	second := NewScoped(scope, vault).ScrubText("Email ann@example.com again")

	if !strings.Contains(first, "[EMAIL_1]") || !strings.Contains(second, "[EMAIL_1]") {
		t.Fatalf("expected stable placeholder across scrubbers; first=%s second=%s", first, second)
	}

	rehydrated, err := vault.RehydrateText(context.Background(), scope, "Reply to [EMAIL_1]")
	if err != nil {
		t.Fatal(err)
	}
	if rehydrated != "Reply to ann@example.com" {
		t.Fatalf("unexpected rehydration: %s", rehydrated)
	}
}

type stubSecretDetector struct {
	finding Finding
}

func (s stubSecretDetector) Find(_ context.Context, _ string) ([]Finding, error) {
	return []Finding{s.finding}, nil
}

func TestGitleaksDetectorRedactsProviderSecret(t *testing.T) {
	detector, err := NewGitleaksDetector()
	if err != nil {
		t.Fatal(err)
	}
	input := `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`
	out := NewWithDetectors(detector).ScrubText(input)
	if strings.Contains(out, "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5") {
		t.Fatalf("expected gitleaks secret redacted: %s", out)
	}
	if !strings.Contains(out, "[SECRET_1]") {
		t.Fatalf("expected secret placeholder: %s", out)
	}
}
