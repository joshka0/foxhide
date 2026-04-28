package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pii-proxy-poc/internal/scrubber"
)

var errCheckFailed = errors.New("pii findings present")

type result struct {
	Path          string         `json:"path,omitempty"`
	Changed       bool           `json:"changed"`
	BytesIn       int            `json:"bytes_in"`
	BytesOut      int            `json:"bytes_out"`
	Findings      map[string]int `json:"findings"`
	Passes        int            `json:"passes,omitempty"`
	VerifiedClean bool           `json:"verified_clean,omitempty"`
	Backup        string         `json:"backup,omitempty"`
	BackupRemoved bool           `json:"backup_removed,omitempty"`
}

func main() {
	var (
		policyFile      string
		contentType     string
		outputPath      string
		inPlace         bool
		check           bool
		jsonSummary     bool
		useGitleaks     bool
		profile         string
		untilClean      bool
		maxPasses       int
		backup          bool
		removeBackup    bool
		entities        string
		excludeEntities string
	)

	flag.StringVar(&policyFile, "policy-file", "", "optional JSON scrub policy file")
	flag.StringVar(&contentType, "content-type", "", "content type hint, e.g. application/json")
	flag.StringVar(&outputPath, "output", "", "write sanitized stdin or single input file to this path")
	flag.BoolVar(&inPlace, "in-place", false, "rewrite input file paths atomically with sanitized content")
	flag.BoolVar(&check, "check", false, "do not write; exit 2 if any input would be changed")
	flag.BoolVar(&jsonSummary, "json-summary", false, "write machine-readable summary to stderr")
	flag.BoolVar(&useGitleaks, "gitleaks", true, "enable Gitleaks default secret rules")
	flag.StringVar(&profile, "profile", "transcript", "scrub profile: transcript or broad")
	flag.BoolVar(&untilClean, "until-clean", false, "repeat scrubbing until a post-check is clean")
	flag.IntVar(&maxPasses, "max-passes", 3, "maximum passes for --until-clean")
	flag.BoolVar(&backup, "backup", false, "create a .pre-pii-scrub.bak before in-place writes")
	flag.BoolVar(&removeBackup, "remove-backup-on-clean", false, "remove .pre-pii-scrub.bak only after verified clean")
	flag.StringVar(&entities, "entities", "SECRET", "comma-separated entity types to scrub; use all for every detector")
	flag.StringVar(&excludeEntities, "exclude-entities", "", "comma-separated entity types to ignore")
	flag.Parse()

	if err := run(options{policyFile: policyFile, contentType: contentType, outputPath: outputPath, inPlace: inPlace, check: check, jsonSummary: jsonSummary, useGitleaks: useGitleaks, profile: profile, untilClean: untilClean, maxPasses: maxPasses, backup: backup, removeBackupOnClean: removeBackup, entities: entities, excludeEntities: excludeEntities}, flag.Args(), os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, errCheckFailed) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "pii-scrub:", err)
		os.Exit(1)
	}
}

type options struct {
	policyFile, contentType, outputPath string
	inPlace, check, jsonSummary         bool
	useGitleaks                         bool
	profile                             string
	untilClean                          bool
	maxPasses                           int
	backup, removeBackupOnClean         bool
	entities, excludeEntities           string
}

func run(opts options, paths []string, stdin io.Reader, stdout, stderr io.Writer) error {
	policy := scrubber.DefaultPayloadPolicy()
	if opts.policyFile != "" {
		loaded, err := scrubber.LoadPayloadPolicyFile(opts.policyFile)
		if err != nil {
			return err
		}
		policy = loaded
	}

	if opts.check && (opts.inPlace || opts.outputPath != "") {
		return fmt.Errorf("--check cannot be combined with --in-place or --output")
	}
	if opts.inPlace && opts.outputPath != "" {
		return fmt.Errorf("--in-place cannot be combined with --output")
	}
	if opts.inPlace && len(paths) == 0 {
		return fmt.Errorf("--in-place requires at least one file path")
	}
	if opts.outputPath != "" && len(paths) > 1 {
		return fmt.Errorf("--output accepts stdin or one input file")
	}
	if len(paths) > 1 && !opts.inPlace && !opts.check {
		return fmt.Errorf("multiple files require --in-place or --check")
	}
	if opts.untilClean && !opts.inPlace {
		return fmt.Errorf("--until-clean requires --in-place")
	}
	if opts.removeBackupOnClean && !opts.backup {
		return fmt.Errorf("--remove-backup-on-clean requires --backup")
	}
	if opts.maxPasses <= 0 {
		return fmt.Errorf("--max-passes must be positive")
	}
	allowEntities, denyEntities, err := parseEntityFilters(opts.entities, opts.excludeEntities)
	if err != nil {
		return err
	}

	detectors, err := transcriptDetectors(opts.useGitleaks)
	if err != nil {
		return err
	}
	scrubProfile, err := parseProfile(opts.profile)
	if err != nil {
		return err
	}

	results := []result{}
	changed := false

	if len(paths) == 0 {
		body, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		out, res := scrubBytes("", body, opts.contentType, policy, detectors, scrubProfile, allowEntities, denyEntities)
		results = append(results, res)
		changed = changed || res.Changed
		if !opts.check {
			if opts.outputPath != "" {
				if err := os.WriteFile(opts.outputPath, out, 0o600); err != nil {
					return err
				}
			} else if _, err := stdout.Write(out); err != nil {
				return err
			}
		}
		return finish(results, changed, opts.check, opts.jsonSummary, stderr)
	}

	for _, path := range paths {
		out, res, err := scrubPath(path, opts, policy, detectors, scrubProfile, allowEntities, denyEntities)
		if err != nil {
			return err
		}
		results = append(results, res)
		changed = changed || res.Changed
		if opts.check {
			continue
		}
		switch {
		case opts.inPlace:
			if res.Changed {
				if err := writeFileAtomic(path, out); err != nil {
					return err
				}
			}
		case opts.outputPath != "":
			if err := os.WriteFile(opts.outputPath, out, 0o600); err != nil {
				return err
			}
		default:
			if _, err := stdout.Write(out); err != nil {
				return err
			}
		}
	}

	return finish(results, changed, opts.check, opts.jsonSummary, stderr)
}

func scrubPath(path string, opts options, policy scrubber.PayloadPolicy, detectors []scrubber.Detector, scrubProfile scrubber.Profile, allowEntities, denyEntities []scrubber.EntityType) ([]byte, result, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, result{}, err
	}
	if opts.backup && opts.inPlace {
		if err := ensureBackup(path); err != nil {
			return nil, result{}, err
		}
	}

	if !opts.untilClean {
		out, res := scrubBytes(path, body, opts.contentType, policy, detectors, scrubProfile, allowEntities, denyEntities)
		if opts.backup && opts.inPlace {
			res.Backup = backupPath(path)
		}
		return out, res, nil
	}

	current := body
	var aggregate result
	for pass := 1; pass <= opts.maxPasses; pass++ {
		out, res := scrubBytes(path, current, opts.contentType, policy, detectors, scrubProfile, allowEntities, denyEntities)
		if pass == 1 {
			aggregate = res
		} else {
			aggregate.Changed = aggregate.Changed || res.Changed
			aggregate.BytesOut = res.BytesOut
			aggregate.Findings = mergeFindings(aggregate.Findings, res.Findings)
		}
		aggregate.Passes = pass
		current = out
		if !res.Changed {
			aggregate.VerifiedClean = true
			break
		}
	}
	if opts.backup && opts.inPlace {
		aggregate.Backup = backupPath(path)
	}
	if !aggregate.VerifiedClean {
		_, check := scrubBytes(path, current, opts.contentType, policy, detectors, scrubProfile, allowEntities, denyEntities)
		aggregate.VerifiedClean = !check.Changed
	}
	if aggregate.VerifiedClean && opts.removeBackupOnClean && aggregate.Backup != "" {
		if err := os.Remove(aggregate.Backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, result{}, err
		}
		aggregate.BackupRemoved = true
		aggregate.Backup = ""
	}
	return current, aggregate, nil
}

func ensureBackup(path string) error {
	backup := backupPath(path)
	if _, err := os.Stat(backup); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(backup, body, info.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

func backupPath(path string) string {
	return path + ".pre-pii-scrub.bak"
}

func mergeFindings(a, b map[string]int) map[string]int {
	if a == nil {
		a = map[string]int{}
	}
	for k, v := range b {
		a[k] += v
	}
	return a
}

func transcriptDetectors(useGitleaks bool) ([]scrubber.Detector, error) {
	if !useGitleaks {
		return nil, nil
	}
	detector, err := scrubber.NewGitleaksDetector()
	if err != nil {
		return nil, fmt.Errorf("gitleaks detector: %w", err)
	}
	return []scrubber.Detector{detector}, nil
}

func parseProfile(profile string) (scrubber.Profile, error) {
	switch scrubber.Profile(profile) {
	case "", scrubber.ProfileTranscript:
		return scrubber.ProfileTranscript, nil
	case scrubber.ProfileBroad:
		return scrubber.ProfileBroad, nil
	default:
		return "", fmt.Errorf("--profile must be transcript or broad")
	}
}

func scrubBytes(path string, body []byte, contentType string, policy scrubber.PayloadPolicy, detectors []scrubber.Detector, profile scrubber.Profile, allowEntities, denyEntities []scrubber.EntityType) ([]byte, result) {
	sc := scrubber.NewWithProfile(profile, detectors...)
	sc.SetEntityFilter(allowEntities, denyEntities)
	out := scrubber.ScrubPayloadWithPolicy(body, contentType, sc, policy)
	return out, result{
		Path:     path,
		Changed:  !bytes.Equal(out, body),
		BytesIn:  len(body),
		BytesOut: len(out),
		Findings: sc.Summary(),
	}
}

func parseEntityFilters(entities, exclude string) ([]scrubber.EntityType, []scrubber.EntityType, error) {
	allow, err := parseEntityList(entities, true)
	if err != nil {
		return nil, nil, err
	}
	deny, err := parseEntityList(exclude, false)
	if err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

func parseEntityList(raw string, allowAllKeyword bool) ([]scrubber.EntityType, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if allowAllKeyword && strings.EqualFold(raw, "all") {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]scrubber.EntityType, 0, len(parts))
	for _, part := range parts {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		entity, ok := knownEntityTypes[part]
		if !ok {
			return nil, fmt.Errorf("unknown entity type %q", part)
		}
		out = append(out, entity)
	}
	return out, nil
}

var knownEntityTypes = map[string]scrubber.EntityType{
	"SECRET":        scrubber.EntitySecret,
	"CREDIT_CARD":   scrubber.EntityCreditCard,
	"SSN":           scrubber.EntitySSN,
	"EMAIL":         scrubber.EntityEmail,
	"PHONE":         scrubber.EntityPhone,
	"IP_ADDRESS":    scrubber.EntityIP,
	"IP":            scrubber.EntityIP,
	"URL":           scrubber.EntityURL,
	"DOB":           scrubber.EntityDOB,
	"ADDRESS":       scrubber.EntityAddress,
	"PERSON":        scrubber.EntityPerson,
	"ID":            scrubber.EntityID,
	"IBAN":          scrubber.EntityIBAN,
	"MODEL_PRIVATE": scrubber.EntityModel,
}

func finish(results []result, changed bool, check, jsonSummary bool, stderr io.Writer) error {
	if jsonSummary {
		enc := json.NewEncoder(stderr)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return err
		}
	} else {
		for _, res := range results {
			path := res.Path
			if path == "" {
				path = "<stdin>"
			}
			fmt.Fprintf(stderr, "%s changed=%t findings=%s\n", path, res.Changed, compactSummary(res.Findings))
		}
	}
	if check && changed {
		return errCheckFailed
	}
	return nil
}

func writeFileAtomic(path string, body []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func compactSummary(summary map[string]int) string {
	if len(summary) == 0 {
		return "none"
	}
	b, first := "", true
	for _, key := range []string{"SECRET", "CREDIT_CARD", "SSN", "EMAIL", "PHONE", "IP_ADDRESS", "URL", "DOB", "ADDRESS", "PERSON", "ID", "IBAN", "MODEL_PRIVATE"} {
		if summary[key] == 0 {
			continue
		}
		if !first {
			b += ","
		}
		b += fmt.Sprintf("%s:%d", key, summary[key])
		first = false
	}
	if b == "" {
		return "none"
	}
	return b
}
