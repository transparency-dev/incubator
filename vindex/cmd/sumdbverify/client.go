// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sumdbverify looks up versions for a Go module in a Go Checksum Verifiable Index
// and compares those verified entries against local git tags and zip/go.mod hashes.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/zip"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

const (
	maxHTTPResponseBytes = 8 << 20 // 8 MiB
	maxErrorBodyBytes    = 4 << 10 // 4 KiB
	fetchConcurrency     = 8
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err := run(ctx, os.Args[1:], os.Stdout)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sumdbverify", flag.ContinueOnError)
	vindexURL := fs.String("vindex_url", "", "Base URL of the server hosting the SumDB VIndex.")
	inputLogURLFlag := fs.String("input_log_url", "", "Base URL of the tiled SumDB Input Log (defaults to <vindex_url>/sumdb/).")
	inputLogOrigin := fs.String("input_log_origin", "go.sum database tree", "Expected origin for the Input Log.")
	inputLogPolicy := fs.String("input_log_policy", "", "Optional path to C2SP tlog-policy file to verify Input Log checkpoint consistency.")
	inputLogPubKey := fs.String("input_log_pubkey", "", "Optional public key or key file to verify Input Log checkpoint consistency.")
	outputLogPolicy := fs.String("output_log_policy", "", "Path to C2SP tlog-policy file for the Output Log.")
	outputLogPubKey := fs.String("output_log_pubkey", "", "Public key or key file to verify the Output Log checkpoint.")
	outputLogOrigin := fs.String("output_log_origin", "", "Expected origin for the Output Log (inferred from --output_log_policy or --output_log_pubkey when unset).")
	modRoot := fs.String("mod_root", "", "Path to a Go module directory checked out locally via git.")
	maxFrom := fs.Uint64("max_from", 0, "Maximum acceptable VIndex start index (from); defaults to 0 so suffix-indexed instances cannot silently omit older releases.")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	targetBaseURL := strings.TrimSpace(*vindexURL)
	targetModRoot := strings.TrimSpace(*modRoot)
	if targetModRoot == "" {
		return errors.New("--mod_root flag must be provided")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	var sumFetcher func(ctx context.Context, modName string) (map[string]modData, error)
	if targetBaseURL == "" {
		klog.Warning("--vindex_url is not provided. Using NON-VERIFIABLE lookup to source SumDB data.")
		sumFetcher = func(ctx context.Context, modName string) (map[string]modData, error) {
			return fetchUnverifiedSumDB(ctx, httpClient, modName)
		}
	} else {
		inOrigin := strings.TrimSpace(*inputLogOrigin)
		if inOrigin == "" {
			return errors.New("--input_log_origin cannot be empty")
		}
		if strings.TrimSpace(*inputLogPolicy) != "" && strings.TrimSpace(*inputLogPubKey) != "" {
			return errors.New("cannot specify both --input_log_policy and --input_log_pubkey")
		}
		var inPolicy wire.Policy
		if strings.TrimSpace(*inputLogPolicy) != "" || strings.TrimSpace(*inputLogPubKey) != "" {
			var err error
			inPolicy, err = wire.ParsePolicyOrVerifier(*inputLogPolicy, *inputLogPubKey, inOrigin, nil, 0)
			if err != nil {
				return fmt.Errorf("failed to build input log policy: %w", err)
			}
		}

		rawInLogURL := strings.TrimSpace(*inputLogURLFlag)
		if rawInLogURL == "" {
			var err error
			rawInLogURL, err = url.JoinPath(targetBaseURL, "/sumdb/")
			if err != nil {
				return fmt.Errorf("failed to construct input log URL: %w", err)
			}
		}
		parsedInURL, err := parseInputLogURL(rawInLogURL)
		if err != nil {
			return err
		}

		cli, err := newClient(httpClient, targetBaseURL, *outputLogPolicy, *outputLogPubKey, *outputLogOrigin, inOrigin)
		if err != nil {
			return err
		}
		sumFetcher = func(ctx context.Context, modName string) (map[string]modData, error) {
			return queryIndex(ctx, httpClient, cli, parsedInURL, inOrigin, inPolicy, modName, *maxFrom)
		}
	}

	report, reportErr := getReport(ctx, targetModRoot, sumFetcher)
	if reportErr != nil && len(report.versions) == 0 {
		return fmt.Errorf("failed to compile report: %w", reportErr)
	}

	_, _ = fmt.Fprintf(out, "%s (./%s)\n", report.modName, report.modPath)

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "VERSION\tINDEX\tFOUND\tgo.mod\tzip\t"); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}
	var reportErrors []error
	if reportErr != nil {
		reportErrors = append(reportErrors, reportErr)
	}
	for _, v := range report.versions {
		if !v.sumFound {
			reportErrors = append(reportErrors, fmt.Errorf("local git tag %q is missing from SumDB", v.version))
			if _, err := fmt.Fprintf(tw, "%s\t--\t✅\t--\t--\t\n", v.version); err != nil {
				return fmt.Errorf("failed to output report: %w", err)
			}
			continue
		}
		sumIndex := strconv.FormatUint(v.sumIndex, 10)

		gitHash := "✅"
		if v.gitCommit == "" {
			gitHash = "❌"
		}

		goMod := "✅"
		if v.gitCommit == "" || v.gitModHash == "" {
			goMod = "⚠️"
		} else if v.gitModHash != v.sumModHash {
			reportErrors = append(reportErrors, fmt.Errorf("failed to reproduce go.mod hash for version %q", v.version))
			goMod = "❌"
		}

		goZip := "✅"
		if v.gitCommit == "" || v.gitZipHash == "" {
			goZip = "⚠️"
		} else if v.gitZipHash != v.sumZipHash {
			reportErrors = append(reportErrors, fmt.Errorf("failed to reproduce zip hash for version %q", v.version))
			goZip = "❌"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", v.version, sumIndex, gitHash, goMod, goZip); err != nil {
			return fmt.Errorf("failed to output report: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush report: %w", err)
	}

	return errors.Join(reportErrors...)
}

func parseInputLogURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid --input_log_url %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return nil, fmt.Errorf("invalid --input_log_url %q: host is required", raw)
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
	case "file":
		if (u.Host != "" && u.Host != "localhost") || u.Path == "" {
			return nil, fmt.Errorf("invalid --input_log_url %q: expected file:///path", raw)
		}
	default:
		return nil, fmt.Errorf("invalid --input_log_url %q: scheme must be http, https, or file", raw)
	}
	return u, nil
}

func sanitizeErrorBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func fetchUnverifiedSumDB(ctx context.Context, httpClient *http.Client, modName string) (map[string]modData, error) {
	escaped, err := module.EscapePath(modName)
	if err != nil {
		return nil, fmt.Errorf("failed to escape module path %q: %w", modName, err)
	}
	body, err := httpGetBody(ctx, httpClient, fmt.Sprintf("https://proxy.golang.org/%s/@v/list", escaped))
	if err != nil {
		return nil, fmt.Errorf("failed to get module listing: %w", err)
	}
	var vers []string
	for v := range strings.Lines(string(body)) {
		if v = strings.TrimSpace(v); v != "" {
			vers = append(vers, v)
		}
	}

	result := make(map[string]modData, len(vers))
	var mu sync.Mutex
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(fetchConcurrency)

	for _, v := range vers {
		eg.Go(func() error {
			escVer, err := module.EscapeVersion(v)
			if err != nil {
				return fmt.Errorf("failed to escape version %q: %w", v, err)
			}
			vBody, err := httpGetBody(egCtx, httpClient, fmt.Sprintf("https://sum.golang.org/lookup/%s@%s", escaped, escVer))
			if err != nil {
				return fmt.Errorf("failed to get version info for %q@%q: %w", modName, v, err)
			}
			beforeNote, _, hasBlank := bytes.Cut(vBody, []byte("\n\n"))
			if !hasBlank {
				beforeNote = bytes.TrimSuffix(vBody, []byte("\n"))
			}
			idxLine, record, ok := bytes.Cut(beforeNote, []byte("\n"))
			if !ok {
				return fmt.Errorf("unexpected lookup response for %q@%q", modName, v)
			}
			idx, err := strconv.ParseUint(string(idxLine), 10, 64)
			if err != nil {
				return fmt.Errorf("failed to parse index: %w", err)
			}
			v2, md, err := parseLeaf(idx, append(record, '\n'), modName)
			if err != nil {
				return fmt.Errorf("failed to parse leaf: %w", err)
			}
			if v != v2 {
				return fmt.Errorf("performed lookup for %q@%q but got version %q", modName, v, v2)
			}
			mu.Lock()
			result[v] = md
			mu.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

func httpGetBody(ctx context.Context, httpClient *http.Client, reqURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		errBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitizeErrorBody(errBytes))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxHTTPResponseBytes {
		return nil, fmt.Errorf("HTTP response exceeded %d bytes", maxHTTPResponseBytes)
	}
	return body, nil
}

func runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if stderr := bytes.TrimSpace(exitErr.Stderr); len(stderr) > 0 {
				return nil, fmt.Errorf("%w: %s", err, stderr)
			}
		}
		return nil, err
	}
	return out, nil
}

func resolveRealDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if realPath, err := filepath.EvalSymlinks(abs); err == nil {
		return realPath, nil
	}
	return abs, nil
}

// localModule encapsulates Go VCS module layout metadata for a checked-out module.
// See https://go.dev/ref/mod#vcs-version.
type localModule struct {
	repoRoot  string
	subdir    string
	codeRoot  string
	tagPrefix string
	majorSub  string // non-empty (e.g. "v2") only for slash-prefixed pathMajor ("/v2")
	modName   string
	pathMajor string
}

func newLocalModule(repoRoot, subdir, modName, pathMajor string) localModule {
	var majorSub string
	if strings.HasPrefix(pathMajor, "/") {
		majorSub = strings.TrimPrefix(pathMajor, "/")
	}
	codeRoot := subdir
	if majorSub != "" {
		switch {
		case subdir == majorSub:
			codeRoot = ""
		case strings.HasSuffix(subdir, "/"+majorSub):
			codeRoot = strings.TrimSuffix(subdir, "/"+majorSub)
		}
	}
	var tagPrefix string
	if codeRoot != "" {
		tagPrefix = codeRoot + "/"
	}
	return localModule{
		repoRoot:  repoRoot,
		subdir:    subdir,
		codeRoot:  codeRoot,
		tagPrefix: tagPrefix,
		majorSub:  majorSub,
		modName:   modName,
		pathMajor: pathMajor,
	}
}

func listGitCommitTags(ctx context.Context, repoRoot string) (map[string]string, error) {
	out, err := runGit(ctx, repoRoot, "for-each-ref",
		"--format=%(refname:strip=2)%09%(*objecttype)%09%(*objectname)%09%(objecttype)%09%(objectname)",
		"refs/tags")
	if err != nil {
		return nil, fmt.Errorf("failed to list git tags: %w", err)
	}
	tags := make(map[string]string)
	for line := range strings.Lines(string(out)) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 5 {
			continue
		}
		tagName, peeledType, peeledSHA, objType, objSHA := parts[0], parts[1], parts[2], parts[3], parts[4]
		switch {
		case peeledType == "commit" && peeledSHA != "":
			tags[tagName] = peeledSHA
		case objType == "commit" && objSHA != "":
			tags[tagName] = objSHA
		}
	}
	return tags, nil
}

func gitBlobAtCommit(ctx context.Context, repoRoot, commitHex, relPath string) ([]byte, bool, error) {
	out, err := runGit(ctx, repoRoot, "ls-tree", commitHex, "--", relPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to inspect %s:%s: %w", commitHex, relPath, err)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, false, nil
	}
	meta, filePath, ok := strings.Cut(line, "\t")
	if !ok || filePath != relPath {
		return nil, false, nil
	}
	fields := strings.Fields(meta)
	if len(fields) != 3 {
		return nil, false, nil
	}
	mode, objType, blobSHA := fields[0], fields[1], fields[2]
	if objType != "blob" || (mode != "100644" && mode != "100755") {
		return nil, false, nil
	}
	blob, err := runGit(ctx, repoRoot, "cat-file", "blob", blobSHA)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read %s:%s: %w", commitHex, relPath, err)
	}
	return blob, true, nil
}

func getReport(ctx context.Context, modRoot string, sumFetcher func(context.Context, string) (map[string]modData, error)) (diffReport, error) {
	info, err := os.Stat(modRoot)
	if err != nil || !info.IsDir() {
		return diffReport{}, fmt.Errorf("mod_root %q does not exist or is not a directory", modRoot)
	}
	absModRoot, err := resolveRealDir(modRoot)
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to resolve mod_root %q: %w", modRoot, err)
	}

	modPathBytes, err := os.ReadFile(filepath.Join(absModRoot, "go.mod"))
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to read go.mod in %q: %w", absModRoot, err)
	}
	modName := modfile.ModulePath(modPathBytes)
	if modName == "" {
		return diffReport{}, errors.New("failed to parse module path from go.mod")
	}
	_, pathMajor, ok := module.SplitPathVersion(modName)
	if !ok {
		return diffReport{}, fmt.Errorf("invalid module path %q in go.mod", modName)
	}

	topOut, err := runGit(ctx, absModRoot, "rev-parse", "--show-toplevel")
	if err != nil {
		return diffReport{}, fmt.Errorf("git rev-parse in mod_root %q failed: %w", modRoot, err)
	}
	repoRoot, err := resolveRealDir(strings.TrimSpace(string(topOut)))
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to resolve git repository root: %w", err)
	}

	relDir, err := filepath.Rel(repoRoot, absModRoot)
	if err != nil || strings.HasPrefix(relDir, "..") {
		return diffReport{}, fmt.Errorf("mod_root %q is outside git repository root %q", absModRoot, repoRoot)
	}
	subdir := ""
	relModPath := "go.mod"
	if relDir != "." {
		subdir = filepath.ToSlash(relDir)
		relModPath = path.Join(subdir, "go.mod")
	}

	mod := newLocalModule(repoRoot, subdir, modName, pathMajor)
	report := diffReport{
		modName:  modName,
		modPath:  relModPath,
		versions: make([]versionReport, 0),
	}

	eg, egCtx := errgroup.WithContext(ctx)
	var versions map[string]modData
	var tagCommits map[string]string

	eg.Go(func() error {
		var fErr error
		versions, fErr = sumFetcher(egCtx, modName)
		return fErr
	})
	eg.Go(func() error {
		var gErr error
		tagCommits, gErr = listGitCommitTags(egCtx, repoRoot)
		return gErr
	})
	if err := eg.Wait(); err != nil {
		return report, err
	}

	sv := make([]string, 0, len(versions))
	for v := range versions {
		sv = append(sv, v)
	}
	semver.Sort(sv)

	var vErrors []error
	for _, v := range sv {
		sumHashes := versions[v]
		rawTag := mod.tagPrefix + strings.TrimSuffix(v, "+incompatible")
		commitHex := tagCommits[rawTag]
		vr, err := mod.reportVersion(ctx, rawTag, v, commitHex)
		if err != nil {
			vErrors = append(vErrors, fmt.Errorf("failed to verify version %q: %w", v, err))
		}
		vr.sumFound = true
		vr.sumModHash = sumHashes.modHash
		vr.sumZipHash = sumHashes.zipHash
		vr.sumIndex = sumHashes.index
		report.versions = append(report.versions, vr)
		if commitHex != "" {
			delete(tagCommits, rawTag)
		}
	}

	for rawTag, commitHex := range tagCommits {
		if ctx.Err() != nil {
			vErrors = append(vErrors, ctx.Err())
			break
		}
		if !strings.HasPrefix(rawTag, mod.tagPrefix) {
			continue
		}
		v := strings.TrimPrefix(rawTag, mod.tagPrefix)
		if !semver.IsValid(v) || semver.Build(v) != "" || semver.Canonical(v) != v || module.IsPseudoVersion(v) {
			continue
		}

		canonicalVer, _, _, _, matches, err := mod.resolveCommit(ctx, v, commitHex)
		if err != nil {
			vErrors = append(vErrors, fmt.Errorf("failed to inspect local tag %q: %w", rawTag, err))
			continue
		}
		if !matches {
			continue
		}
		report.versions = append(report.versions, versionReport{
			version:   canonicalVer,
			gitCommit: commitHex,
			sumFound:  false,
		})
	}

	slices.SortFunc(report.versions, func(a, b versionReport) int {
		if c := semver.Compare(a.version, b.version); c != 0 {
			return c
		}
		return strings.Compare(a.version, b.version)
	})
	return report, errors.Join(vErrors...)
}

// resolveCommit evaluates Go VCS module attribution rules (https://go.dev/ref/mod#vcs-version)
// for a semver tag baseVer (without "+incompatible") at commitHex.
func (m *localModule) resolveCommit(ctx context.Context, baseVer, commitHex string) (canonicalVer string, modBlob []byte, hasMod bool, commitSubdir string, matches bool, err error) {
	if module.CheckPathMajor(baseVer, m.pathMajor) != nil {
		// A v2+ tag without a /vN module path suffix is only valid as "+incompatible"
		// on a root v0/v1 module when neither go.mod nor vN/go.mod exists at commitHex.
		if m.pathMajor != "" || m.codeRoot != "" {
			return "", nil, false, "", false, nil
		}
		if _, rootHasMod, gErr := gitBlobAtCommit(ctx, m.repoRoot, commitHex, "go.mod"); gErr != nil || rootHasMod {
			return "", nil, false, "", false, gErr
		}
		majorDirMod := path.Join(semver.Major(baseVer), "go.mod")
		if _, hasMajorMod, gErr := gitBlobAtCommit(ctx, m.repoRoot, commitHex, majorDirMod); gErr != nil || hasMajorMod {
			return "", nil, false, "", false, gErr
		}
		return baseVer + "+incompatible", nil, false, "", true, nil
	}

	primaryModPath := "go.mod"
	if m.subdir != "" {
		primaryModPath = path.Join(m.subdir, "go.mod")
	}
	blob, found, gErr := gitBlobAtCommit(ctx, m.repoRoot, commitHex, primaryModPath)
	if gErr != nil {
		return "", nil, false, "", false, gErr
	}

	if m.majorSub != "" {
		if found && modfile.ModulePath(blob) == m.modName {
			return baseVer, blob, true, m.subdir, true, nil
		}
		// Check alternate major-branch (<codeRoot>/go.mod) vs major-subdirectory (<codeRoot>/vN/go.mod) layout.
		altSubdir := path.Join(m.codeRoot, m.majorSub)
		if m.subdir == altSubdir {
			altSubdir = m.codeRoot
		}
		altModPath := "go.mod"
		if altSubdir != "" {
			altModPath = path.Join(altSubdir, "go.mod")
		}
		altBlob, altFound, altErr := gitBlobAtCommit(ctx, m.repoRoot, commitHex, altModPath)
		if altErr != nil || !altFound || modfile.ModulePath(altBlob) != m.modName {
			return "", nil, false, "", false, altErr
		}
		return baseVer, altBlob, true, altSubdir, true, nil
	}

	if found {
		if modfile.ModulePath(blob) != m.modName {
			return "", nil, false, "", false, nil
		}
		return baseVer, blob, true, m.subdir, true, nil
	}
	// Pre-module releases without go.mod (including gopkg.in/*.vN) are valid only at the repository root.
	if m.codeRoot != "" {
		return "", nil, false, "", false, nil
	}
	return baseVer, nil, false, "", true, nil
}

func (m *localModule) reportVersion(ctx context.Context, rawTag, v, commitHex string) (versionReport, error) {
	report := versionReport{version: v, gitCommit: commitHex}
	if !semver.IsValid(v) {
		return report, fmt.Errorf("invalid semver version %q", v)
	}
	if commitHex == "" {
		return report, fmt.Errorf("git tag %q not found in repository", rawTag)
	}

	baseVer := strings.TrimSuffix(v, "+incompatible")
	canonicalVer, modBlob, hasMod, commitSubdir, matches, err := m.resolveCommit(ctx, baseVer, commitHex)
	if err != nil {
		return report, err
	}
	if !matches || canonicalVer != v {
		return report, fmt.Errorf("commit %s (tag %q) does not match Go module %q@%q", commitHex, rawTag, m.modName, v)
	}

	if hasMod {
		hs, hErr := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(modBlob)), nil
		})
		if hErr != nil {
			return report, fmt.Errorf("failed to calculate go.mod hash: %w", hErr)
		}
		report.gitModHash = hs
	}

	f, err := os.CreateTemp("", "sumdbverify-zip-*")
	if err != nil {
		return report, fmt.Errorf("failed to create temp file: %w", err)
	}
	zipName := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(zipName)
	}()

	modVer := module.Version{Path: m.modName, Version: v}
	if err := zip.CreateFromVCS(f, modVer, m.repoRoot, commitHex, commitSubdir); err != nil {
		return report, fmt.Errorf("failed to create zip file: %w", err)
	}
	if err := f.Close(); err != nil {
		return report, fmt.Errorf("failed to close zip file: %w", err)
	}
	report.gitZipHash, err = dirhash.HashZip(zipName, dirhash.Hash1)
	if err != nil {
		return report, fmt.Errorf("failed to hash zip file: %w", err)
	}

	return report, nil
}

type diffReport struct {
	modName  string
	modPath  string
	versions []versionReport
}

type versionReport struct {
	version    string
	gitCommit  string
	gitModHash string
	gitZipHash string

	sumFound   bool
	sumIndex   uint64
	sumModHash string
	sumZipHash string
}

type modData struct {
	index   uint64
	zipHash string
	modHash string
}

func verifyInputLogConsistency(
	ctx context.Context,
	httpClient *http.Client,
	res *client.LookupResult,
	inLogURL *url.URL,
	inOrigin string,
	inPolicy wire.Policy,
) error {
	if inPolicy == nil {
		return nil
	}
	tf, err := ingest.NewTiledFetcher(inLogURL, nil, inOrigin, httpClient)
	if err != nil {
		return fmt.Errorf("failed to initialize Input Log fetcher: %w", err)
	}
	tf.SetPolicy(inPolicy)
	inCP, err := tf.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to verify signed Input Log checkpoint: %w", err)
	}
	if inCP.Origin != inOrigin {
		return fmt.Errorf("input log checkpoint origin %q != expected %q", inCP.Origin, inOrigin)
	}
	if inCP.Size == 0 && inCP.Hash != wire.EmptyRoot() {
		return fmt.Errorf("input log size-0 checkpoint has non-empty root %x", inCP.Hash)
	}
	if res.InputSize > inCP.Size {
		return fmt.Errorf("VIndex committed input-size %d exceeds signed Input Log checkpoint size %d", res.InputSize, inCP.Size)
	}
	switch res.InputSize {
	case 0:
		return nil
	case inCP.Size:
		if res.InputRoot != inCP.Hash {
			return fmt.Errorf("input log split-view at size %d: VIndex committed %x, Input Log signed %x", res.InputSize, res.InputRoot, inCP.Hash)
		}
	default:
		cProof, err := tf.ConsistencyProof(ctx, res.InputSize, inCP.Size)
		if err != nil {
			return fmt.Errorf("failed to fetch Input Log consistency proof (%d -> %d): %w", res.InputSize, inCP.Size, err)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, res.InputSize, inCP.Size, cProof, res.InputRoot[:], inCP.Hash[:]); err != nil {
			return fmt.Errorf("input log consistency proof (%d -> %d) failed: %w", res.InputSize, inCP.Size, err)
		}
	}
	return nil
}

func queryIndex(
	ctx context.Context,
	httpClient *http.Client,
	cli *client.Client,
	inLogURL *url.URL,
	inOrigin string,
	inPolicy wire.Policy,
	modName string,
	maxFromHorizon uint64,
) (map[string]modData, error) {
	escapedMod, err := module.EscapePath(modName)
	if err != nil {
		return nil, fmt.Errorf("failed to escape module path %q: %w", modName, err)
	}
	keysResp, err := cli.LookupKey(ctx, escapedMod)
	if err != nil {
		return nil, fmt.Errorf("failed to look up key: %w", err)
	}
	if keysResp.From > maxFromHorizon {
		return nil, fmt.Errorf("VIndex covers entries starting at from=%d (exceeds --max_from=%d); historical releases before %d would be omitted", keysResp.From, maxFromHorizon, keysResp.From)
	}
	if err := verifyInputLogConsistency(ctx, httpClient, keysResp, inLogURL, inOrigin, inPolicy); err != nil {
		return nil, err
	}

	versions := make(map[string]modData)
	if len(keysResp.Keys) == 0 {
		return versions, nil
	}

	var indices []uint64
	for idx, err := range keysResp.Keys[0].Values(ctx) {
		if err != nil {
			return nil, fmt.Errorf("failed to look up values: %w", err)
		}
		indices = append(indices, idx)
	}

	inURLStr := inLogURL.String()
	var mu sync.Mutex
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(fetchConcurrency)

	for _, idx := range indices {
		eg.Go(func() error {
			leafData, err := ingest.FetchVerifiedEntryByIndex(egCtx, httpClient, inURLStr, idx, keysResp.InputSize, keysResp.InputRoot)
			if err != nil {
				return fmt.Errorf("failed to get leaf at index %d: %w", idx, err)
			}
			version, data, err := parseLeaf(idx, leafData, modName)
			if err != nil {
				return fmt.Errorf("failed to parse leaf at index %d: %w", idx, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if prev, found := versions[version]; found {
				return fmt.Errorf("conflicting entries for version %q found: %v vs %v", version, prev, data)
			}
			versions[version] = data
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return versions, nil
}

func parseLeaf(idx uint64, data []byte, expectedMod string) (string, modData, error) {
	trimmed := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 2 {
		return "", modData{}, fmt.Errorf("expected 2 lines, got %d", len(lines))
	}

	f0 := strings.Fields(lines[0])
	if len(f0) != 3 || !strings.HasPrefix(f0[2], "h1:") {
		return "", modData{}, fmt.Errorf("invalid line 0 format: %q", lines[0])
	}
	line0Module, line0Version, zipHashB64 := f0[0], f0[1], f0[2]

	f1 := strings.Fields(lines[1])
	if len(f1) != 3 || !strings.HasPrefix(f1[2], "h1:") {
		return "", modData{}, fmt.Errorf("invalid line 1 format: %q", lines[1])
	}
	line1Version, hasGoModSuffix := strings.CutSuffix(f1[1], "/go.mod")
	if !hasGoModSuffix {
		return "", modData{}, fmt.Errorf("invalid line 1 format (missing /go.mod): %q", lines[1])
	}
	line1Module, modHashB64 := f1[0], f1[2]

	if line0Module != line1Module {
		return "", modData{}, fmt.Errorf("mismatched module names: (%q, %q)", line0Module, line1Module)
	}
	if expectedMod != "" && line0Module != expectedMod {
		return "", modData{}, fmt.Errorf("leaf module %q does not match expected module %q", line0Module, expectedMod)
	}
	if line0Version != line1Version {
		return "", modData{}, fmt.Errorf("mismatched version names: (%q, %q)", line0Version, line1Version)
	}

	return line0Version, modData{
		index:   idx,
		zipHash: zipHashB64,
		modHash: modHashB64,
	}, nil
}

func newClient(httpClient *http.Client, targetBaseURL, outputPolicyPath, outputPubKey, outputOrigin, inputOrigin string) (*client.Client, error) {
	policyPath := strings.TrimSpace(outputPolicyPath)
	pubKey := strings.TrimSpace(outputPubKey)
	if policyPath == "" && pubKey == "" {
		return nil, errors.New("--output_log_policy or --output_log_pubkey flag must be provided when --vindex_url is set")
	}
	if policyPath != "" && pubKey != "" {
		return nil, errors.New("cannot specify both --output_log_policy and --output_log_pubkey")
	}

	outOrigin := strings.TrimSpace(outputOrigin)
	outPolicy, err := wire.ParsePolicyOrVerifier(policyPath, pubKey, outOrigin, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to build output log policy: %w", err)
	}
	if outOrigin == "" && wire.PolicyOrigin(outPolicy) == "" {
		return nil, errors.New("--output_log_origin is required when --output_log_policy contains multiple logs")
	}

	return client.New(targetBaseURL, client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  inputOrigin,
	}, client.WithHTTPClient(httpClient))
}
