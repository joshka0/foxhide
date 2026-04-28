package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"pii-proxy-poc/internal/scrubber"
)

type config struct {
	listenAddr, upstreamAuthHdr, upstreamAuthVal string
	upstreamBase                                 *url.URL
	maxBodyBytes                                 int64
	scrubResponse, rehydrateResponse             bool
	scrubQueryParams, forwardSensitiveHeaders    bool
	logRequestPath                               bool
	denyOnTypes                                  map[string]struct{}
	policy                                       scrubber.PayloadPolicy
	detectors                                    []scrubber.Detector
	vault                                        scrubber.Vault
	authMode                                     string
	orgID                                        string
	requireWorkspace, requireConversation        bool
	allowedGroups                                map[string]struct{}
	client                                       *http.Client
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/", cfg.handle)
	srv := &http.Server{Addr: cfg.listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	upstream := "echo-mode"
	if cfg.upstreamBase != nil {
		upstream = cfg.upstreamBase.String()
	}
	log.Printf("pii-proxy listening addr=%s upstream=%s max_body_bytes=%d json_mode=%s scrub_response=%t rehydrate_response=%t", cfg.listenAddr, upstream, cfg.maxBodyBytes, cfg.policy.JSONMode, cfg.scrubResponse, cfg.rehydrateResponse)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() (*config, error) {
	maxBodyBytes, err := getenvInt64("MAX_BODY_BYTES", 2*1024*1024)
	if err != nil {
		return nil, err
	}
	timeoutSeconds, err := getenvInt64("UPSTREAM_TIMEOUT_SECONDS", 60)
	if err != nil {
		return nil, err
	}
	detectorTimeoutSeconds, err := getenvInt64("PRIVACY_FILTER_TIMEOUT_SECONDS", 30)
	if err != nil {
		return nil, err
	}
	detectorMinScore, err := getenvFloat("PRIVACY_FILTER_MIN_SCORE", 0.85)
	if err != nil {
		return nil, err
	}
	policy := scrubber.DefaultPayloadPolicy()
	if p := strings.TrimSpace(os.Getenv("POLICY_FILE")); p != "" {
		loaded, err := scrubber.LoadPayloadPolicyFile(p)
		if err != nil {
			return nil, fmt.Errorf("POLICY_FILE: %w", err)
		}
		policy = loaded
	}
	if raw := strings.TrimSpace(os.Getenv("SCRUB_JSON_MODE")); raw != "" {
		policy.JSONMode = scrubber.JSONMode(strings.ToLower(raw))
	}
	if raw := strings.TrimSpace(os.Getenv("SCRUB_INCLUDE_PATHS")); raw != "" {
		policy.IncludePaths = splitCSV(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("SCRUB_EXCLUDE_PATHS")); raw != "" {
		policy.ExcludePaths = splitCSV(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("REDACT_SENSITIVE_JSON_KEYS")); raw != "" {
		policy.RedactSensitiveJSONKeys = getenvBool("REDACT_SENSITIVE_JSON_KEYS", true)
	}
	if raw := strings.TrimSpace(os.Getenv("SCRUB_PLAIN_TEXT")); raw != "" {
		policy.ScrubPlainText = getenvBool("SCRUB_PLAIN_TEXT", true)
	}
	policy = policy.Normalize()
	var upstream *url.URL
	if raw := strings.TrimSpace(os.Getenv("UPSTREAM_BASE_URL")); raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("UPSTREAM_BASE_URL: %w", err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("UPSTREAM_BASE_URL must include scheme and host")
		}
		upstream = parsed
	}
	var detectors []scrubber.Detector
	if getenvBool("GITLEAKS_ENABLED", true) {
		gitleaksDetector, err := scrubber.NewGitleaksDetector()
		if err != nil {
			return nil, fmt.Errorf("gitleaks detector: %w", err)
		}
		detectors = append(detectors, gitleaksDetector)
	}
	if raw := strings.TrimSpace(os.Getenv("PRIVACY_FILTER_URL")); raw != "" {
		detectors = append(detectors, &scrubber.ExternalDetector{
			URL:      raw,
			MinScore: detectorMinScore,
			Client:   &http.Client{Timeout: time.Duration(detectorTimeoutSeconds) * time.Second},
		})
	}
	var vault scrubber.Vault
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VAULT_BACKEND"))) {
	case "", "memory":
		vault = scrubber.NewMemoryVault()
	case "postgres":
		pgVault, err := scrubber.NewPostgresVault(
			context.Background(),
			os.Getenv("DATABASE_URL"),
			os.Getenv("PII_HMAC_KEY"),
			os.Getenv("PII_ENCRYPTION_KEY"),
			getenvBool("VAULT_AUTO_MIGRATE", true),
		)
		if err != nil {
			return nil, fmt.Errorf("postgres vault: %w", err)
		}
		vault = pgVault
	default:
		return nil, fmt.Errorf("VAULT_BACKEND must be memory or postgres")
	}

	authMode := strings.ToLower(getenv("AUTH_MODE", "dev"))
	if authMode != "dev" && authMode != "alb_oidc" {
		return nil, fmt.Errorf("AUTH_MODE must be dev or alb_oidc")
	}

	return &config{listenAddr: getenv("LISTEN_ADDR", ":8080"), upstreamBase: upstream, upstreamAuthHdr: strings.TrimSpace(os.Getenv("UPSTREAM_AUTH_HEADER")), upstreamAuthVal: strings.TrimSpace(os.Getenv("UPSTREAM_AUTH_VALUE")), maxBodyBytes: maxBodyBytes, scrubResponse: getenvBool("SCRUB_RESPONSE", false), rehydrateResponse: getenvBool("REHYDRATE_RESPONSE", false), scrubQueryParams: getenvBool("SCRUB_QUERY_PARAMS", true), forwardSensitiveHeaders: getenvBool("FORWARD_SENSITIVE_HEADERS", false), logRequestPath: getenvBool("LOG_REQUEST_PATH", false), denyOnTypes: parseTypeSet(os.Getenv("DENY_ON_TYPES")), policy: policy, detectors: detectors, vault: vault, authMode: authMode, orgID: getenv("ORG_ID", "default"), requireWorkspace: getenvBool("REQUIRE_WORKSPACE", true), requireConversation: getenvBool("REQUIRE_CONVERSATION", true), allowedGroups: parseTypeSet(os.Getenv("ALLOWED_GROUPS")), client: &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}}, nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (cfg *config) handle(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	scope, err := cfg.resolveScope(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		cfg.logSafe(r, http.StatusUnauthorized, nil, started)
		return
	}
	body, err := readLimited(r.Body, cfg.maxBodyBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	defer r.Body.Close()
	sc := cfg.newScrubber(scope)
	sanitized := scrubber.ScrubPayloadWithPolicyContext(r.Context(), body, r.Header.Get("Content-Type"), sc, cfg.policy)
	query := r.URL.Query()
	if cfg.scrubQueryParams {
		query = scrubber.ScrubQueryValuesContext(r.Context(), query, sc)
	}
	summary := sc.Summary()
	addPIIHeaders(w.Header(), summary)
	if denied := deniedSummary(summary, cfg.denyOnTypes); len(denied) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "request contains a disallowed sensitive entity type", "denied_types": denied, "findings": summary})
		cfg.recordAudit(r, scope, sanitized, summary, true, http.StatusBadRequest)
		cfg.logSafe(r, http.StatusBadRequest, summary, started)
		return
	}
	if cfg.upstreamBase == nil {
		cfg.writeEcho(w, r, sanitized, query, summary, started)
		cfg.recordAudit(r, scope, sanitized, summary, false, http.StatusOK)
		cfg.logSafe(r, http.StatusOK, summary, started)
		return
	}
	requestPlaceholders := sc.PlaceholderMap()
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, cfg.targetURL(r, query), bytes.NewReader(sanitized))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}
	copyHeaders(r.Header, upstreamReq.Header, cfg.forwardSensitiveHeaders)
	upstreamReq.ContentLength = int64(len(sanitized))
	mutateResponse := cfg.scrubResponse || cfg.rehydrateResponse
	if mutateResponse {
		upstreamReq.Header.Del("Accept-Encoding")
	}
	if cfg.upstreamAuthHdr != "" && cfg.upstreamAuthVal != "" {
		upstreamReq.Header.Set(cfg.upstreamAuthHdr, cfg.upstreamAuthVal)
	}
	upstreamResp, err := cfg.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		cfg.recordAudit(r, scope, sanitized, summary, false, http.StatusBadGateway)
		cfg.logSafe(r, http.StatusBadGateway, summary, started)
		return
	}
	defer upstreamResp.Body.Close()
	copyResponseHeaders(upstreamResp.Header, w.Header())
	addPIIHeaders(w.Header(), summary)
	if !mutateResponse {
		w.WriteHeader(upstreamResp.StatusCode)
		copyBodyStreaming(w, upstreamResp.Body)
		cfg.recordAudit(r, scope, sanitized, summary, false, upstreamResp.StatusCode)
		cfg.logSafe(r, upstreamResp.StatusCode, summary, started)
		return
	}
	responseBody, err := readLimited(upstreamResp.Body, cfg.maxBodyBytes)
	if err != nil {
		http.Error(w, "upstream response too large to transform", http.StatusBadGateway)
		cfg.recordAudit(r, scope, sanitized, summary, false, http.StatusBadGateway)
		cfg.logSafe(r, http.StatusBadGateway, summary, started)
		return
	}
	out := responseBody
	if cfg.scrubResponse {
		out = scrubber.ScrubPayloadWithPolicy(out, upstreamResp.Header.Get("Content-Type"), sc, cfg.policy)
	}
	if cfg.rehydrateResponse {
		out = scrubber.RehydratePayloadWithVault(r.Context(), out, upstreamResp.Header.Get("Content-Type"), cfg.vault, scope, requestPlaceholders)
	}
	w.Header().Del("Content-Length")
	addPIIHeaders(w.Header(), sc.Summary())
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(out)
	cfg.recordAudit(r, scope, sanitized, sc.Summary(), false, upstreamResp.StatusCode)
	cfg.logSafe(r, upstreamResp.StatusCode, sc.Summary(), started)
}

func (cfg *config) writeEcho(w http.ResponseWriter, r *http.Request, sanitized []byte, query url.Values, summary map[string]int, started time.Time) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"mode": "echo", "path": cfg.displayPath(r), "sanitized_query": query.Encode(), "redacted": totalFindings(summary) > 0, "findings": summary, "elapsed_ms": time.Since(started).Milliseconds(), "json_mode": cfg.policy.JSONMode, "sanitized_body": string(sanitized), "response_rehydration_on": cfg.rehydrateResponse})
}
func (cfg *config) newScrubber(scope scrubber.Scope) *scrubber.Scrubber {
	return scrubber.NewScoped(scope, cfg.vault, cfg.detectors...)
}
func (cfg *config) targetURL(r *http.Request, query url.Values) string {
	u := *cfg.upstreamBase
	u.Path = singleJoiningSlash(cfg.upstreamBase.Path, r.URL.Path)
	u.RawQuery = query.Encode()
	return u.String()
}
func (cfg *config) resolveScope(r *http.Request) (scrubber.Scope, error) {
	userID := "dev-user"
	claimOrgID := ""
	var groups []string

	if cfg.authMode == "alb_oidc" {
		raw := strings.TrimSpace(r.Header.Get("x-amzn-oidc-data"))
		if raw == "" {
			return scrubber.Scope{}, fmt.Errorf("missing ALB OIDC identity")
		}
		claims, err := decodeJWTClaims(raw)
		if err != nil {
			return scrubber.Scope{}, fmt.Errorf("invalid ALB OIDC identity")
		}
		userID = firstStringClaim(claims, "email", "preferred_username", "upn", "sub")
		if userID == "" {
			return scrubber.Scope{}, fmt.Errorf("ALB OIDC identity has no user claim")
		}
		claimOrgID = firstStringClaim(claims, "tid", "tenant", "org_id")
		groups = stringSliceClaim(claims, "groups", "roles")
		if len(cfg.allowedGroups) > 0 && !hasAllowedGroup(groups, cfg.allowedGroups) {
			return scrubber.Scope{}, fmt.Errorf("user is not authorized for this proxy")
		}
	} else if h := strings.TrimSpace(r.Header.Get("X-User-ID")); h != "" {
		userID = h
	}

	orgID := strings.TrimSpace(r.Header.Get("X-Org-ID"))
	if orgID == "" {
		orgID = claimOrgID
	}
	if orgID == "" {
		orgID = cfg.orgID
	}

	workspaceID := strings.TrimSpace(r.Header.Get("X-Workspace-ID"))
	if workspaceID == "" && !cfg.requireWorkspace {
		workspaceID = "default"
	}
	if workspaceID == "" {
		return scrubber.Scope{}, fmt.Errorf("missing X-Workspace-ID")
	}

	conversationID := strings.TrimSpace(r.Header.Get("X-Conversation-ID"))
	if conversationID == "" && !cfg.requireConversation {
		conversationID = "default"
	}
	if conversationID == "" {
		return scrubber.Scope{}, fmt.Errorf("missing X-Conversation-ID")
	}

	return scrubber.Scope{
		OrgID:          orgID,
		WorkspaceID:    workspaceID,
		ConversationID: conversationID,
		UserID:         userID,
	}, nil
}

func readLimited(rc io.Reader, max int64) ([]byte, error) {
	if rc == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("body exceeds MAX_BODY_BYTES=%d", max)
	}
	return body, nil
}

var hopByHopHeaders = map[string]struct{}{"Connection": {}, "Keep-Alive": {}, "Proxy-Authenticate": {}, "Proxy-Authorization": {}, "Te": {}, "Trailer": {}, "Transfer-Encoding": {}, "Upgrade": {}, "Content-Length": {}}
var sensitiveRequestHeaders = map[string]struct{}{"Authorization": {}, "Cookie": {}, "Set-Cookie": {}, "X-Api-Key": {}, "X-Auth-Token": {}, "X-Forwarded-For": {}, "X-Real-Ip": {}, "Forwarded": {}, "Cf-Connecting-Ip": {}, "True-Client-Ip": {}}

func copyHeaders(src http.Header, dst http.Header, forwardSensitive bool) {
	for k, vals := range src {
		canonical := http.CanonicalHeaderKey(k)
		if _, skip := hopByHopHeaders[canonical]; skip {
			continue
		}
		if !forwardSensitive {
			if _, skip := sensitiveRequestHeaders[canonical]; skip {
				continue
			}
		}
		dst.Del(canonical)
		for _, v := range vals {
			dst.Add(canonical, v)
		}
	}
}
func copyResponseHeaders(src http.Header, dst http.Header) {
	for k, vals := range src {
		canonical := http.CanonicalHeaderKey(k)
		if _, skip := hopByHopHeaders[canonical]; skip {
			continue
		}
		dst.Del(canonical)
		for _, v := range vals {
			dst.Add(canonical, v)
		}
	}
}
func copyBodyStreaming(w http.ResponseWriter, body io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	reader := bufio.NewReaderSize(body, len(buf))
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
func addPIIHeaders(h http.Header, summary map[string]int) {
	h.Set("X-PII-Proxy-Findings", strconv.Itoa(totalFindings(summary)))
	if len(summary) == 0 {
		h.Set("X-PII-Proxy-Entities", "none")
		return
	}
	keys := make([]string, 0, len(summary))
	for k := range summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, summary[k]))
	}
	h.Set("X-PII-Proxy-Entities", strings.Join(parts, ","))
}
func totalFindings(summary map[string]int) int {
	total := 0
	for _, n := range summary {
		total += n
	}
	return total
}
func deniedSummary(summary map[string]int, denied map[string]struct{}) []string {
	if len(summary) == 0 || len(denied) == 0 {
		return nil
	}
	out := []string{}
	for entity := range summary {
		if _, ok := denied[strings.ToUpper(entity)]; ok {
			out = append(out, entity)
		}
	}
	sort.Strings(out)
	return out
}
func singleJoiningSlash(a, b string) string {
	aslash, bslash := strings.HasSuffix(a, "/"), strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}
func getenv(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
func getenvInt64(name string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}
func getenvFloat(name string, fallback float64) (float64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n < 0 || n > 1 {
		return 0, fmt.Errorf("%s must be a number between 0 and 1", name)
	}
	return n, nil
}
func getenvBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}
func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
func parseTypeSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range splitCSV(raw) {
		out[strings.ToUpper(p)] = struct{}{}
	}
	return out
}
func decodeJWTClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
func firstStringClaim(claims map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := claims[name].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func stringSliceClaim(claims map[string]any, names ...string) []string {
	out := []string{}
	for _, name := range names {
		switch value := claims[name].(type) {
		case string:
			if value != "" {
				out = append(out, value)
			}
		case []any:
			for _, item := range value {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}
func hasAllowedGroup(groups []string, allowed map[string]struct{}) bool {
	for _, group := range groups {
		if _, ok := allowed[strings.ToUpper(group)]; ok {
			return true
		}
	}
	return false
}
func (cfg *config) logSafe(r *http.Request, status int, summary map[string]int, started time.Time) {
	path := "redacted"
	if cfg.logRequestPath {
		path = r.URL.EscapedPath()
	}
	log.Printf("method=%s path=%s status=%d findings=%d entities=%s latency_ms=%d", r.Method, path, status, totalFindings(summary), compactSummary(summary), time.Since(started).Milliseconds())
}
func (cfg *config) displayPath(r *http.Request) string {
	if cfg.logRequestPath {
		return r.URL.RequestURI()
	}
	return "redacted"
}
func (cfg *config) recordAudit(r *http.Request, scope scrubber.Scope, body []byte, summary map[string]int, denied bool, statusCode int) {
	recorder, ok := cfg.vault.(scrubber.AuditRecorder)
	if !ok {
		return
	}
	event := scrubber.AuditEvent{
		RequestID:     requestID(r),
		UpstreamModel: modelFromPayload(body),
		Findings:      summary,
		Denied:        denied,
		StatusCode:    statusCode,
	}
	if err := recorder.RecordAuditEvent(r.Context(), scope, event); err != nil {
		log.Printf("audit_record_failed err=%q", err.Error())
	}
}
func requestID(r *http.Request) string {
	for _, h := range []string{"X-Request-ID", "X-Correlation-ID", "X-Amzn-Trace-Id"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return fmt.Sprintf("local-%d", time.Now().UnixNano())
}
func modelFromPayload(body []byte) string {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ""
	}
	model, _ := decoded["model"].(string)
	if len(model) > 200 {
		return model[:200]
	}
	return model
}
func compactSummary(summary map[string]int) string {
	if len(summary) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(summary))
	for k := range summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, summary[k]))
	}
	return strings.Join(parts, ",")
}
