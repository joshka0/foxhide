package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScrubsStdinToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(testOptions("text/plain", false, false, false), nil, strings.NewReader("Email ann@example.com and token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "ann@example.com") || strings.Contains(stdout.String(), "ghp_") {
		t.Fatalf("expected stdout scrubbed, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "[EMAIL_") || !strings.Contains(stdout.String(), "[SECRET_1]") {
		t.Fatalf("expected only secret placeholder by default, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "changed=true") {
		t.Fatalf("expected summary on stderr, got %q", stderr.String())
	}
}

func TestRunCheckReturnsExitSignalWithoutWriting(t *testing.T) {
	var stdout, stderr bytes.Buffer
	opts := testOptions("text/plain", false, true, false)
	err := run(opts, nil, strings.NewReader("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"), &stdout, &stderr)
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("expected errCheckFailed, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("check mode should not write stdout, got %q", stdout.String())
	}
}

func TestRunInPlaceRewritesFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.txt")
	if err := os.WriteFile(path, []byte("Call 415-555-1212 or email ann@example.com"), 0o640); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := run(testOptions("text/plain", true, false, true), []string{path}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "415-555-1212") || !strings.Contains(string(body), "ann@example.com") {
		t.Fatalf("expected non-secret entities preserved by default, got %q", string(body))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("expected mode preserved, got %v", info.Mode().Perm())
	}
	if !strings.Contains(stderr.String(), `"findings": {}`) {
		t.Fatalf("expected json summary, got %q", stderr.String())
	}
}

func TestRunInPlacePreservesJSONLRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	body := "{\"content\":\"token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD\"}\n{\"content\":\"Email bob@example.com\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := run(testOptions("", true, false, true), []string{path}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ghp_") || !strings.Contains(string(out), "bob@example.com") {
		t.Fatalf("expected JSONL secrets scrubbed and non-secret email preserved, got %q", string(out))
	}
	if strings.Count(string(out), "\n") != 2 {
		t.Fatalf("expected both JSONL records preserved, got %q", string(out))
	}
}

func TestRunUntilCleanRemovesVerifiedBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.txt")
	if err := os.WriteFile(path, []byte("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := testOptions("text/plain", true, false, true)
	opts.untilClean = true
	opts.maxPasses = 3
	opts.backup = true
	opts.removeBackupOnClean = true

	var stdout, stderr bytes.Buffer
	if err := run(opts, []string{path}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(backupPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected verified backup removed, stat err=%v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "ghp_") {
		t.Fatalf("expected file scrubbed clean, got %q", string(body))
	}
	if !strings.Contains(stderr.String(), `"verified_clean": true`) || !strings.Contains(stderr.String(), `"backup_removed": true`) {
		t.Fatalf("expected verified cleanup summary, got %q", stderr.String())
	}
}

func TestRunCanOptIntoAdditionalEntities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	opts := testOptions("text/plain", false, false, false)
	opts.entities = "SECRET,EMAIL"
	err := run(opts, nil, strings.NewReader("Email ann@example.com and token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "ann@example.com") || strings.Contains(stdout.String(), "ghp_") {
		t.Fatalf("expected email and secret scrubbed, got %q", stdout.String())
	}
}

func testOptions(contentType string, inPlace, check, jsonSummary bool) options {
	return options{
		contentType: contentType,
		inPlace:     inPlace,
		check:       check,
		jsonSummary: jsonSummary,
		useGitleaks: true,
		profile:     "transcript",
		maxPasses:   3,
		entities:    "SECRET",
	}
}
