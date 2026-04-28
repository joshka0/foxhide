package scrubber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type EntityType string

const (
	EntitySecret     EntityType = "SECRET"
	EntityCreditCard EntityType = "CREDIT_CARD"
	EntitySSN        EntityType = "SSN"
	EntityEmail      EntityType = "EMAIL"
	EntityPhone      EntityType = "PHONE"
	EntityIP         EntityType = "IP_ADDRESS"
	EntityURL        EntityType = "URL"
	EntityDOB        EntityType = "DOB"
	EntityAddress    EntityType = "ADDRESS"
	EntityPerson     EntityType = "PERSON"
	EntityID         EntityType = "ID"
	EntityIBAN       EntityType = "IBAN"
	EntityModel      EntityType = "MODEL_PRIVATE"
)

type Detector interface {
	Find(ctx context.Context, text string) ([]Finding, error)
}

type ExternalDetector struct {
	URL      string
	MinScore float64
	Client   *http.Client
}

func (d *ExternalDetector) Find(ctx context.Context, text string) ([]Finding, error) {
	if d == nil || strings.TrimSpace(d.URL) == "" || text == "" {
		return nil, nil
	}

	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}

	minScore := d.MinScore
	if minScore <= 0 || minScore > 1 {
		minScore = 0.85
	}

	reqBody, err := json.Marshal(map[string]any{
		"text":      text,
		"min_score": minScore,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(d.URL, "/")+"/detect", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("privacy detector returned status %d", resp.StatusCode)
	}

	var decoded struct {
		Detections []struct {
			Entity string  `json:"entity"`
			Score  float64 `json:"score"`
			Start  int     `json:"start"`
			End    int     `json:"end"`
			Text   string  `json:"text"`
		} `json:"detections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(decoded.Detections))
	for _, d := range decoded.Detections {
		if d.Start < 0 || d.End > len(text) || d.Start >= d.End {
			continue
		}
		value := d.Text
		if value == "" {
			value = text[d.Start:d.End]
		}
		findings = append(findings, Finding{
			Type:  mapModelEntity(d.Entity),
			Start: d.Start,
			End:   d.End,
			Value: value,
		})
	}
	return findings, nil
}

func mapModelEntity(entity string) EntityType {
	switch strings.ToLower(strings.TrimSpace(entity)) {
	case "private_email", "email":
		return EntityEmail
	case "private_phone", "phone", "phone_number":
		return EntityPhone
	case "private_person", "person", "name":
		return EntityPerson
	case "private_address", "address", "location":
		return EntityAddress
	case "private_ip", "ip", "ip_address":
		return EntityIP
	case "private_url", "url":
		return EntityURL
	case "private_credential", "credential", "secret", "password":
		return EntitySecret
	case "private_id", "id":
		return EntityID
	default:
		return EntityModel
	}
}

type JSONMode string

const (
	JSONModeAllStrings JSONMode = "all_strings"
	JSONModeSchema     JSONMode = "schema"
)

type PayloadPolicy struct {
	JSONMode                JSONMode `json:"json_mode"`
	IncludePaths            []string `json:"include_paths"`
	ExcludePaths            []string `json:"exclude_paths"`
	RedactSensitiveJSONKeys bool     `json:"redact_sensitive_json_keys"`
	ScrubPlainText          bool     `json:"scrub_plain_text"`
}

func DefaultPayloadPolicy() PayloadPolicy {
	return PayloadPolicy{JSONMode: JSONModeAllStrings, IncludePaths: DefaultIncludePaths(), ExcludePaths: DefaultExcludePaths(), RedactSensitiveJSONKeys: true, ScrubPlainText: true}
}
func DefaultIncludePaths() []string {
	return []string{"messages.*.content", "messages.*.content.*.text", "input", "input.*.content", "input.*.content.*.text", "prompt", "prompts.*", "system", "instructions", "conversation.*.content", "metadata.*"}
}
func DefaultExcludePaths() []string {
	return []string{"model", "role", "stream", "temperature", "top_p", "max_tokens", "max_completion_tokens", "tool_choice", "response_format.type", "tools.*.function.name", "functions.*.name"}
}
func (p PayloadPolicy) Normalize() PayloadPolicy {
	if p.JSONMode == "" {
		p.JSONMode = JSONModeAllStrings
	}
	mode := JSONMode(strings.ToLower(strings.TrimSpace(string(p.JSONMode))))
	if mode != JSONModeAllStrings && mode != JSONModeSchema {
		mode = JSONModeAllStrings
	}
	p.JSONMode = mode
	if p.IncludePaths == nil {
		p.IncludePaths = DefaultIncludePaths()
	}
	if p.ExcludePaths == nil {
		p.ExcludePaths = DefaultExcludePaths()
	}
	return p
}
func LoadPayloadPolicyFile(path string) (PayloadPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return PayloadPolicy{}, err
	}
	p := DefaultPayloadPolicy()
	if err := json.Unmarshal(b, &p); err != nil {
		return PayloadPolicy{}, err
	}
	return p.Normalize(), nil
}

type Finding struct {
	Type       EntityType
	Start, End int
	Value      string
}

type Scrubber struct {
	counters     map[EntityType]int
	replacements map[string]string
	originals    map[string]string
	Findings     []Finding
	detectors    []Detector
	profile      Profile
	allowTypes   map[EntityType]struct{}
	denyTypes    map[EntityType]struct{}
	vault        Vault
	scope        Scope
}

type Profile string

const (
	ProfileBroad      Profile = "broad"
	ProfileTranscript Profile = "transcript"
)

func New() *Scrubber {
	return &Scrubber{counters: map[EntityType]int{}, replacements: map[string]string{}, originals: map[string]string{}, profile: ProfileBroad}
}
func NewWithDetectors(detectors ...Detector) *Scrubber {
	sc := New()
	sc.detectors = detectors
	return sc
}
func NewWithProfile(profile Profile, detectors ...Detector) *Scrubber {
	sc := NewWithDetectors(detectors...)
	sc.profile = normalizeProfile(profile)
	return sc
}
func (s *Scrubber) SetEntityFilter(allow, deny []EntityType) {
	if s == nil {
		return
	}
	s.allowTypes = entitySet(allow)
	s.denyTypes = entitySet(deny)
}
func NewScoped(scope Scope, vault Vault, detectors ...Detector) *Scrubber {
	sc := NewWithDetectors(detectors...)
	sc.scope = scope
	sc.vault = vault
	return sc
}
func normalizeProfile(profile Profile) Profile {
	switch Profile(strings.ToLower(strings.TrimSpace(string(profile)))) {
	case ProfileTranscript:
		return ProfileTranscript
	default:
		return ProfileBroad
	}
}
func (s *Scrubber) FindingCount() int {
	if s == nil {
		return 0
	}
	return len(s.Findings)
}
func (s *Scrubber) Summary() map[string]int {
	out := map[string]int{}
	if s == nil {
		return out
	}
	for _, f := range s.Findings {
		out[string(f.Type)]++
	}
	return out
}
func (s *Scrubber) PlaceholderMap() map[string]string {
	out := map[string]string{}
	if s == nil {
		return out
	}
	for k, v := range s.originals {
		out[k] = v
	}
	return out
}

func ScrubPayload(body []byte, contentType string, sc *Scrubber) []byte {
	return ScrubPayloadWithPolicy(body, contentType, sc, DefaultPayloadPolicy())
}
func ScrubPayloadWithPolicy(body []byte, contentType string, sc *Scrubber, policy PayloadPolicy) []byte {
	return ScrubPayloadWithPolicyContext(context.Background(), body, contentType, sc, policy)
}
func ScrubPayloadWithPolicyContext(ctx context.Context, body []byte, contentType string, sc *Scrubber, policy PayloadPolicy) []byte {
	if sc == nil {
		sc = New()
	}
	policy = policy.Normalize()
	trimmed := strings.TrimSpace(string(body))
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if ct == "application/json" || looksLikeJSON(trimmed) {
		var v any
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			var extra any
			if err := dec.Decode(&extra); err == io.EOF {
				if out, err := json.Marshal(scrubJSONValue(ctx, v, sc, policy, nil)); err == nil {
					return out
				}
			}
		}
	}
	if !policy.ScrubPlainText {
		return body
	}
	return []byte(sc.ScrubTextContext(ctx, string(body)))
}

func RehydratePayload(body []byte, contentType string, placeholders map[string]string) []byte {
	if len(placeholders) == 0 || len(body) == 0 {
		return body
	}
	trimmed := strings.TrimSpace(string(body))
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if ct == "application/json" || looksLikeJSON(trimmed) {
		var v any
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			if out, err := json.Marshal(rehydrateJSONValue(v, placeholders)); err == nil {
				return out
			}
		}
	}
	return []byte(RehydrateTextWithMap(string(body), placeholders))
}
func RehydratePayloadWithVault(ctx context.Context, body []byte, contentType string, vault Vault, scope Scope, placeholders map[string]string) []byte {
	out := RehydratePayload(body, contentType, placeholders)
	if vault == nil {
		return out
	}
	rehydrated, err := vault.RehydrateText(ctx, scope, string(out))
	if err != nil {
		return out
	}
	return []byte(rehydrated)
}
func RehydrateTextWithMap(text string, placeholders map[string]string) string {
	if len(placeholders) == 0 || text == "" {
		return text
	}
	keys := make([]string, 0, len(placeholders))
	for k := range placeholders {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	out := text
	for _, k := range keys {
		out = strings.ReplaceAll(out, k, placeholders[k])
	}
	return out
}
func ScrubQueryValues(values url.Values, sc *Scrubber) url.Values {
	return ScrubQueryValuesContext(context.Background(), values, sc)
}
func ScrubQueryValuesContext(ctx context.Context, values url.Values, sc *Scrubber) url.Values {
	out := make(url.Values, len(values))
	if sc == nil {
		sc = New()
	}
	for k, vals := range values {
		entity, whole := SensitiveKeyType(k)
		for _, v := range vals {
			if whole {
				out.Add(k, sc.ScrubWholeValueContext(ctx, entity, v))
			} else {
				out.Add(k, sc.ScrubTextContext(ctx, v))
			}
		}
	}
	return out
}

func looksLikeJSON(s string) bool { return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") }
func scrubJSONValue(ctx context.Context, v any, sc *Scrubber, p PayloadPolicy, path []string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			x[k] = scrubJSONValue(ctx, child, sc, p, appendPath(path, k))
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = scrubJSONValue(ctx, child, sc, p, appendPath(path, "*"))
		}
		return x
	case string:
		last := ""
		if len(path) > 0 {
			last = path[len(path)-1]
		}
		if p.RedactSensitiveJSONKeys {
			if entity, ok := SensitiveKeyType(last); ok {
				return sc.ScrubWholeValueContext(ctx, entity, x)
			}
		}
		if shouldScrubPath(p, path) {
			return sc.ScrubTextContext(ctx, x)
		}
		return x
	default:
		return v
	}
}
func rehydrateJSONValue(v any, placeholders map[string]string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			x[k] = rehydrateJSONValue(child, placeholders)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = rehydrateJSONValue(child, placeholders)
		}
		return x
	case string:
		return RehydrateTextWithMap(x, placeholders)
	default:
		return v
	}
}
func appendPath(path []string, next string) []string {
	out := make([]string, 0, len(path)+1)
	out = append(out, path...)
	return append(out, next)
}
func shouldScrubPath(p PayloadPolicy, path []string) bool {
	if matchAnyPath(p.ExcludePaths, path) {
		return false
	}
	if p.JSONMode == JSONModeAllStrings {
		return true
	}
	return matchAnyPath(p.IncludePaths, path)
}
func matchAnyPath(patterns []string, path []string) bool {
	for _, p := range patterns {
		if matchPathPattern(p, path) {
			return true
		}
	}
	return false
}
func matchPathPattern(pattern string, path []string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	parts := strings.Split(pattern, ".")
	if len(parts) == 1 && len(path) > 0 {
		return parts[0] == "*" || strings.EqualFold(parts[0], path[len(path)-1])
	}
	if len(parts) != len(path) {
		return false
	}
	for i := range parts {
		if parts[i] != "*" && !strings.EqualFold(parts[i], path[i]) {
			return false
		}
	}
	return true
}

func SensitiveKeyType(key string) (EntityType, bool) {
	k := normalizeKey(key)
	if k == "" || k == "*" {
		return "", false
	}
	for _, term := range []string{"apikey", "accesskey", "secret", "clientsecret", "token", "authtoken", "authorization", "password", "passwd", "pwd", "credential", "privatekey", "cookie", "sessionid", "bearer"} {
		if strings.Contains(k, term) {
			return EntitySecret, true
		}
	}
	if strings.Contains(k, "email") {
		return EntityEmail, true
	}
	if strings.Contains(k, "phone") || strings.Contains(k, "mobile") || strings.Contains(k, "telephone") {
		return EntityPhone, true
	}
	if strings.Contains(k, "ssn") || strings.Contains(k, "socialsecurity") {
		return EntitySSN, true
	}
	if strings.Contains(k, "dob") || strings.Contains(k, "dateofbirth") || strings.Contains(k, "birthdate") {
		return EntityDOB, true
	}
	if strings.Contains(k, "address") {
		return EntityAddress, true
	}
	for _, term := range []string{"fullname", "firstname", "lastname", "patientname", "customername", "contactname", "legalname"} {
		if strings.Contains(k, term) {
			return EntityPerson, true
		}
	}
	for _, term := range []string{"accountid", "accountnumber", "customerid", "customernumber", "memberid", "membernumber", "claimid", "claimnumber", "policyid", "policynumber", "patientid", "caseid", "casenumber"} {
		if strings.Contains(k, term) {
			return EntityID, true
		}
	}
	return "", false
}
func normalizeKey(key string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	emailRe          = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	ssnRe            = regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`)
	ipV4Re           = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
	ipV6Re           = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b`)
	jwtRe            = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)
	awsKeyRe         = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	openAIKeyRe      = regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`)
	anthropicKeyRe   = regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)
	githubTokenRe    = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b`)
	slackTokenRe     = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{20,}\b`)
	googleAPIKeyRe   = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}\b`)
	privateKeyRe     = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	creditCardRe     = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	ibanRe           = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	urlWithQueryRe   = regexp.MustCompile(`https?://[^\s"'<>]+\?[^\s"'<>]+`)
	phoneRe          = regexp.MustCompile(`\b(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b`)
	phoneContextRe   = regexp.MustCompile(`(?i)\b(?:phone|mobile|cell|tel|telephone|call)\s*(?:is|:|=)?\s*(\+?[0-9][0-9().\-\s]{6,}[0-9])\b`)
	secretContextRe  = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|bearer)\b\s*[:=]?\s*["']?([A-Za-z0-9_\-./+=]{8,})["']?`)
	bearerHeaderRe   = regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9_\-./+=]{16,})\b`)
	dobContextRe     = regexp.MustCompile(`(?i)\b(?:dob|date of birth|born)\s*(?:is|:|=)?\s*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}|[0-9]{4}-[0-9]{2}-[0-9]{2})\b`)
	nameContextRe    = regexp.MustCompile(`(?i)\b(?:my name is|customer name is|patient name is|user name is|full name is|name\s*[:=]|called)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b`)
	addressRe        = regexp.MustCompile(`(?i)\b(?:address|mailing address|home address|ship(?:ping)? address)\s*(?:is|:|=)?\s*([0-9]{1,6}\s+[A-Za-z0-9 .'\-]{2,60}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b(?:[.,]?\s*[A-Za-z .'\-]{2,40})?)`)
	idContextRe      = regexp.MustCompile(`(?i)\b(?:account|acct|claim|policy|member|customer id|customer number|case|patient id)\s*(?:number|no\.?|#|id)?\s*(?:is|:|=)?\s*([A-Za-z0-9][A-Za-z0-9\-]{4,})\b`)
	projectContextRe = regexp.MustCompile(`\b(?:[Ii]nternal\s+)?(?:[Cc]odename|[Cc]ode name|[Pp]roject|[Pp]rogram|[Ss]ystem name|[Aa]pp name|[Aa]pplication name)\s*(?:is|:|=)?\s+([A-Z][A-Za-z0-9_-]+(?:\s+[A-Z][A-Za-z0-9_-]+){0,3})\b`)
)

type candidate struct {
	Finding
	priority int
}

func (s *Scrubber) ScrubText(text string) string {
	return s.ScrubTextContext(context.Background(), text)
}
func (s *Scrubber) ScrubTextContext(ctx context.Context, text string) string {
	if s == nil || text == "" {
		return text
	}
	findings := s.find(ctx, text)
	if len(findings) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, f := range findings {
		if f.Start < last || f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			continue
		}
		b.WriteString(text[last:f.Start])
		b.WriteString(s.placeholder(ctx, f.Type, f.Value))
		s.Findings = append(s.Findings, f)
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}
func (s *Scrubber) ScrubWholeValue(t EntityType, value string) string {
	return s.ScrubWholeValueContext(context.Background(), t, value)
}
func (s *Scrubber) ScrubWholeValueContext(ctx context.Context, t EntityType, value string) string {
	if s == nil || value == "" {
		return value
	}
	s.Findings = append(s.Findings, Finding{Type: t, Start: 0, End: len(value), Value: value})
	return s.placeholder(ctx, t, value)
}
func (s *Scrubber) placeholder(ctx context.Context, t EntityType, value string) string {
	if s.vault != nil {
		surrogate, err := s.vault.GetOrCreate(ctx, s.scope, t, value, func() string {
			return s.nextPlaceholder(t)
		})
		if err == nil && surrogate != "" {
			s.originals[surrogate] = value
			return surrogate
		}
	}
	return s.nextPlaceholder(t, value)
}

func (s *Scrubber) nextPlaceholder(t EntityType, value ...string) string {
	original := ""
	if len(value) > 0 {
		original = value[0]
	}
	if original == "" {
		s.counters[t]++
		return fmt.Sprintf("[%s_%d]", t, s.counters[t])
	}
	key := string(t) + "\x00" + original
	if existing, ok := s.replacements[key]; ok {
		return existing
	}
	s.counters[t]++
	p := fmt.Sprintf("[%s_%d]", t, s.counters[t])
	s.replacements[key] = p
	s.originals[p] = original
	return p
}

func find(text string) []Finding {
	return findFromCandidates(baseCandidates(text, ProfileBroad))
}
func (s *Scrubber) find(ctx context.Context, text string) []Finding {
	candidates := baseCandidates(text, s.profile)
	for _, detector := range s.detectors {
		findings, err := detector.Find(ctx, text)
		if err != nil {
			continue
		}
		for _, f := range findings {
			if s.profile == ProfileTranscript && isTranscriptFalsePositive(f, text) {
				continue
			}
			candidates = append(candidates, candidate{Finding: f, priority: 85})
		}
	}
	if s.profile == ProfileTranscript {
		candidates = filterTranscriptFalsePositiveCandidates(candidates, text)
	}
	candidates = s.filterEntityCandidates(candidates)
	return findFromCandidates(candidates)
}
func (s *Scrubber) filterEntityCandidates(candidates []candidate) []candidate {
	if s == nil || (len(s.allowTypes) == 0 && len(s.denyTypes) == 0) {
		return candidates
	}
	out := candidates[:0]
	for _, cand := range candidates {
		if len(s.allowTypes) > 0 {
			if _, ok := s.allowTypes[cand.Type]; !ok {
				continue
			}
		}
		if _, ok := s.denyTypes[cand.Type]; ok {
			continue
		}
		out = append(out, cand)
	}
	return out
}
func entitySet(values []EntityType) map[EntityType]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := map[EntityType]struct{}{}
	for _, value := range values {
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
func filterTranscriptFalsePositiveCandidates(candidates []candidate, text string) []candidate {
	out := candidates[:0]
	for _, cand := range candidates {
		if isTranscriptFalsePositive(cand.Finding, text) {
			continue
		}
		out = append(out, cand)
	}
	return out
}
func baseCandidates(text string, profile Profile) []candidate {
	var c []candidate
	addRegex(&c, EntitySecret, privateKeyRe, text, 120)
	addRegex(&c, EntitySecret, jwtRe, text, 110)
	addRegex(&c, EntitySecret, awsKeyRe, text, 110)
	addRegex(&c, EntitySecret, openAIKeyRe, text, 110)
	addRegex(&c, EntitySecret, anthropicKeyRe, text, 110)
	addRegex(&c, EntitySecret, githubTokenRe, text, 110)
	addRegex(&c, EntitySecret, slackTokenRe, text, 110)
	addRegex(&c, EntitySecret, googleAPIKeyRe, text, 110)
	addRegexGroup(&c, EntitySecret, secretContextRe, text, 1, 108, nil)
	addRegexGroup(&c, EntitySecret, bearerHeaderRe, text, 1, 108, nil)
	addCreditCards(&c, text, profile)
	addIBANs(&c, text)
	if profile != ProfileTranscript {
		addRegexValidated(&c, EntitySSN, ssnRe, text, 90, validSSN)
	}
	addRegex(&c, EntityEmail, emailRe, text, 80)
	addRegex(&c, EntityURL, urlWithQueryRe, text, 88)
	addRegex(&c, EntityIP, ipV4Re, text, 70)
	addRegex(&c, EntityIP, ipV6Re, text, 70)
	addRegexGroup(&c, EntityPhone, phoneContextRe, text, 1, 66, validPhone)
	addRegexGroup(&c, EntityDOB, dobContextRe, text, 1, 64, nil)
	addRegexGroup(&c, EntityAddress, addressRe, text, 1, 62, nil)
	if profile != ProfileTranscript {
		addRegexValidated(&c, EntityPhone, phoneRe, text, 65, validPhone)
		addRegexGroup(&c, EntityID, idContextRe, text, 1, 61, nil)
	}
	if profile != ProfileTranscript {
		addRegexGroup(&c, EntityModel, projectContextRe, text, 1, 60, nil)
	}
	addRegexGroup(&c, EntityPerson, nameContextRe, text, 1, 55, likelyHumanName)
	return c
}
func isTranscriptFalsePositive(f Finding, text string) bool {
	if f.Type == EntityModel {
		return true
	}
	if f.Type != EntitySecret {
		return false
	}
	value := strings.TrimSpace(f.Value)
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	context := nearbyLower(text, f.Start, f.End, 48, 48)
	for _, term := range []string{
		"token-classification",
		"secretmanager",
		"secret-manager",
		"secret-store",
		"secret_store",
		"secret files",
		"secret-file",
		"secrets)",
	} {
		if strings.Contains(lower, term) || strings.Contains(context, term) {
			return true
		}
	}
	if strings.EqualFold(value, "secret") || strings.EqualFold(value, "token") {
		return true
	}
	if isIdentifierLikeKeyword(value) {
		if strings.Contains(context, "pipeline") || strings.Contains(context, "type") || strings.Contains(context, "path") || strings.Contains(context, "file") {
			return true
		}
	}
	return false
}

func isIdentifierLikeKeyword(value string) bool {
	lower := strings.ToLower(strings.Trim(value, ` "'`))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "secret") || strings.Contains(lower, "token")
}

func nearbyLower(text string, start, end, leftPad, rightPad int) string {
	left := start - leftPad
	if left < 0 {
		left = 0
	}
	right := end + rightPad
	if right > len(text) {
		right = len(text)
	}
	return strings.ToLower(text[left:right])
}
func findFromCandidates(c []candidate) []Finding {
	return selectNonOverlapping(c)
}
func addRegex(c *[]candidate, t EntityType, re *regexp.Regexp, text string, priority int) {
	addRegexValidated(c, t, re, text, priority, nil)
}
func addRegexValidated(c *[]candidate, t EntityType, re *regexp.Regexp, text string, priority int, valid func(string) bool) {
	for _, loc := range re.FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if valid != nil && !valid(v) {
			continue
		}
		*c = append(*c, candidate{Finding: Finding{Type: t, Start: loc[0], End: loc[1], Value: v}, priority: priority})
	}
}
func addRegexGroup(c *[]candidate, t EntityType, re *regexp.Regexp, text string, group, priority int, valid func(string) bool) {
	for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
		si, ei := group*2, group*2+1
		if len(loc) <= ei || loc[si] < 0 || loc[ei] < 0 {
			continue
		}
		v := text[loc[si]:loc[ei]]
		if valid != nil && !valid(v) {
			continue
		}
		*c = append(*c, candidate{Finding: Finding{Type: t, Start: loc[si], End: loc[ei], Value: v}, priority: priority})
	}
}
func addCreditCards(c *[]candidate, text string, profile Profile) {
	for _, loc := range creditCardRe.FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		d := digitsOnly(v)
		if len(d) < 13 || len(d) > 19 || allSameDigit(d) || !validLuhn(d) {
			continue
		}
		if profile == ProfileTranscript && !hasNearbyCreditCardContext(text, loc[0], loc[1]) {
			continue
		}
		*c = append(*c, candidate{Finding: Finding{Type: EntityCreditCard, Start: loc[0], End: loc[1], Value: v}, priority: 95})
	}
}
func hasNearbyCreditCardContext(text string, start, end int) bool {
	left := start - 80
	if left < 0 {
		left = 0
	}
	right := end + 40
	if right > len(text) {
		right = len(text)
	}
	window := strings.ToLower(text[left:right])
	for _, term := range []string{"credit card", "card number", "card:", "card ", "cc number", "payment card", "visa", "mastercard", "amex"} {
		if strings.Contains(window, term) {
			return true
		}
	}
	return false
}
func addIBANs(c *[]candidate, text string) {
	for _, loc := range ibanRe.FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if !validIBAN(v) {
			continue
		}
		*c = append(*c, candidate{Finding: Finding{Type: EntityIBAN, Start: loc[0], End: loc[1], Value: v}, priority: 94})
	}
}
func selectNonOverlapping(c []candidate) []Finding {
	if len(c) == 0 {
		return nil
	}
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].priority != c[j].priority {
			return c[i].priority > c[j].priority
		}
		li, lj := c[i].End-c[i].Start, c[j].End-c[j].Start
		if li != lj {
			return li > lj
		}
		return c[i].Start < c[j].Start
	})
	selected := make([]candidate, 0, len(c))
	for _, cand := range c {
		overlap := false
		for _, prev := range selected {
			if cand.Start < prev.End && prev.Start < cand.End {
				overlap = true
				break
			}
		}
		if !overlap {
			selected = append(selected, cand)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })
	out := make([]Finding, len(selected))
	for i, cand := range selected {
		out[i] = cand.Finding
	}
	return out
}
func validPhone(v string) bool { d := digitsOnly(v); return len(d) >= 7 && len(d) <= 15 }
func validSSN(v string) bool {
	d := digitsOnly(v)
	if len(d) != 9 || allSameDigit(d) {
		return false
	}
	area, group, serial := d[:3], d[3:5], d[5:]
	return area != "000" && area != "666" && !strings.HasPrefix(area, "9") && group != "00" && serial != "0000"
}
func likelyHumanName(v string) bool {
	parts := strings.Fields(strings.TrimSpace(v))
	if len(parts) == 0 || len(parts) > 4 || len(v) > 80 {
		return false
	}
	for _, p := range parts {
		t := strings.Trim(p, ".'-")
		if len(t) < 2 {
			return false
		}
		r := []rune(t)
		if len(r) == 0 || !unicode.IsUpper(r[0]) {
			return false
		}
	}
	return true
}
func digitsOnly(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func compactAlphaNum(v string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(v) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func allSameDigit(d string) bool {
	if d == "" {
		return true
	}
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}
func validLuhn(d string) bool {
	sum := 0
	dbl := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if dbl {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		dbl = !dbl
	}
	return sum%10 == 0
}
func validIBAN(v string) bool {
	c := compactAlphaNum(v)
	if len(c) < 15 || len(c) > 34 {
		return false
	}
	if len(c) < 4 || !isAlpha(c[0]) || !isAlpha(c[1]) || !isDigit(c[2]) || !isDigit(c[3]) {
		return false
	}
	r := c[4:] + c[:4]
	mod := 0
	for _, ch := range r {
		switch {
		case ch >= '0' && ch <= '9':
			mod = (mod*10 + int(ch-'0')) % 97
		case ch >= 'A' && ch <= 'Z':
			mod = (mod*100 + int(ch-'A') + 10) % 97
		default:
			return false
		}
	}
	return mod == 1
}
func isAlpha(b byte) bool { return b >= 'A' && b <= 'Z' }
func isDigit(b byte) bool { return b >= '0' && b <= '9' }
