package scrubber

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresVault struct {
	db      *sql.DB
	hmacKey []byte
	aead    cipher.AEAD
}

func NewPostgresVault(ctx context.Context, databaseURL, hmacSecret, encryptionSecret string, autoMigrate bool) (*PostgresVault, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("DATABASE_URL is required for postgres vault")
	}
	if hmacSecret == "" {
		return nil, fmt.Errorf("PII_HMAC_KEY is required for postgres vault")
	}
	if encryptionSecret == "" {
		return nil, fmt.Errorf("PII_ENCRYPTION_KEY is required for postgres vault")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	key := sha256.Sum256([]byte(encryptionSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	v := &PostgresVault{db: db, hmacKey: []byte(hmacSecret), aead: aead}
	if autoMigrate {
		if err := v.EnsureSchema(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return v, nil
}

func (v *PostgresVault) Close() error {
	if v == nil || v.db == nil {
		return nil
	}
	return v.db.Close()
}

func (v *PostgresVault) EnsureSchema(ctx context.Context) error {
	_, err := v.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS pii_mappings (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  original_hmac TEXT NOT NULL,
  original_ciphertext BYTEA NOT NULL,
  surrogate TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, workspace_id, conversation_id, entity_type, original_hmac),
  UNIQUE (org_id, workspace_id, conversation_id, surrogate)
);
CREATE INDEX IF NOT EXISTS pii_mappings_scope_idx
  ON pii_mappings (org_id, workspace_id, conversation_id);
CREATE INDEX IF NOT EXISTS pii_mappings_surrogate_idx
  ON pii_mappings (org_id, workspace_id, conversation_id, surrogate);
CREATE TABLE IF NOT EXISTS pii_audit_events (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  upstream_model TEXT,
  findings JSONB NOT NULL DEFAULT '{}'::jsonb,
  denied BOOLEAN NOT NULL DEFAULT false,
  status_code INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE pii_audit_events
  ADD COLUMN IF NOT EXISTS status_code INTEGER;
`)
	return err
}

func (v *PostgresVault) GetOrCreate(ctx context.Context, scope Scope, entity EntityType, original string, next func() string) (string, error) {
	if v == nil {
		return "", fmt.Errorf("nil postgres vault")
	}
	originalHash := v.hmacOriginal(scope, entity, original)

	var surrogate string
	err := v.db.QueryRowContext(ctx, `
UPDATE pii_mappings
SET last_seen_at = now()
WHERE org_id = $1 AND workspace_id = $2 AND conversation_id = $3
  AND entity_type = $4 AND original_hmac = $5
RETURNING surrogate
`, scope.OrgID, scope.WorkspaceID, scope.ConversationID, string(entity), originalHash).Scan(&surrogate)
	if err == nil {
		return surrogate, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	ciphertext, err := v.encrypt(original)
	if err != nil {
		return "", err
	}

	for i := 0; i < 8; i++ {
		surrogate = next()
		err = v.db.QueryRowContext(ctx, `
INSERT INTO pii_mappings (
  org_id, workspace_id, conversation_id, entity_type,
  original_hmac, original_ciphertext, surrogate, created_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT DO NOTHING
RETURNING surrogate
`, scope.OrgID, scope.WorkspaceID, scope.ConversationID, string(entity), originalHash, ciphertext, surrogate, scope.UserID).Scan(&surrogate)
		if err == nil {
			return surrogate, nil
		}
		if err != sql.ErrNoRows {
			return "", err
		}
		err = v.db.QueryRowContext(ctx, `
SELECT surrogate
FROM pii_mappings
WHERE org_id = $1 AND workspace_id = $2 AND conversation_id = $3
  AND entity_type = $4 AND original_hmac = $5
`, scope.OrgID, scope.WorkspaceID, scope.ConversationID, string(entity), originalHash).Scan(&surrogate)
		if err == nil {
			return surrogate, nil
		}
	}
	return "", fmt.Errorf("could not allocate unique surrogate for %s", entity)
}

func (v *PostgresVault) RehydrateText(ctx context.Context, scope Scope, text string) (string, error) {
	if v == nil || text == "" {
		return text, nil
	}

	rows, err := v.db.QueryContext(ctx, `
SELECT surrogate, original_ciphertext
FROM pii_mappings
WHERE org_id = $1 AND workspace_id = $2 AND conversation_id = $3
`, scope.OrgID, scope.WorkspaceID, scope.ConversationID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	type mapping struct {
		surrogate string
		original  string
	}
	mappings := []mapping{}
	for rows.Next() {
		var surrogate string
		var ciphertext []byte
		if err := rows.Scan(&surrogate, &ciphertext); err != nil {
			return "", err
		}
		original, err := v.decrypt(ciphertext)
		if err != nil {
			return "", err
		}
		mappings = append(mappings, mapping{surrogate: surrogate, original: original})
	}
	if err := rows.Err(); err != nil {
		return "", err
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

func (v *PostgresVault) RecordAuditEvent(ctx context.Context, scope Scope, event AuditEvent) error {
	if v == nil {
		return fmt.Errorf("nil postgres vault")
	}
	findings := event.Findings
	if findings == nil {
		findings = map[string]int{}
	}
	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	requestID := strings.TrimSpace(event.RequestID)
	if requestID == "" {
		requestID = "unknown"
	}
	_, err = v.db.ExecContext(ctx, `
INSERT INTO pii_audit_events (
  org_id, workspace_id, conversation_id, user_id, request_id,
  upstream_model, findings, denied, status_code
) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
`, scope.OrgID, scope.WorkspaceID, scope.ConversationID, scope.UserID, requestID, strings.TrimSpace(event.UpstreamModel), string(findingsJSON), event.Denied, event.StatusCode)
	return err
}

func (v *PostgresVault) hmacOriginal(scope Scope, entity EntityType, original string) string {
	mac := hmac.New(sha256.New, v.hmacKey)
	_, _ = mac.Write([]byte(scope.OrgID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(scope.WorkspaceID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(scope.ConversationID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(entity))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(original))
	return hex.EncodeToString(mac.Sum(nil))
}

func (v *PostgresVault) encrypt(plaintext string) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, nonce...)
	out = v.aead.Seal(out, nonce, []byte(plaintext), nil)
	return out, nil
}

func (v *PostgresVault) decrypt(ciphertext []byte) (string, error) {
	if len(ciphertext) < v.aead.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:v.aead.NonceSize()]
	body := ciphertext[v.aead.NonceSize():]
	plaintext, err := v.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
