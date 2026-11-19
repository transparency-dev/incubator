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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/zip"
)

var testExampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var testExampleLeaf2 = []byte(`golang.org/x/text v0.3.1 h1:anotherhash1234567890=
golang.org/x/text v0.3.1/go.mod h1:anothermodhash123456=
`)

func newGitHelper(t *testing.T, repoDir string) func(args ...string) string {
	t.Helper()
	ctx := t.Context()
	return func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_TERMINAL_PROMPT=0",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}
}

func mustModHash(t *testing.T, goModContent []byte) string {
	t.Helper()
	h, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(goModContent)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustZipHash(t *testing.T, repoDir, modPath, ver, commit, subdir string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "zip-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := zip.CreateFromVCS(f, module.Version{Path: modPath, Version: ver}, repoDir, commit, subdir); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	h, err := dirhash.HashZip(f.Name(), dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRun_CLIValidation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tmpDir := t.TempDir()

	if err := run(ctx, []string{"--help"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(--help) = %v, want flag.ErrHelp", err)
	}
	if err := run(ctx, []string{"extra"}, io.Discard); err == nil || !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("run(positional) = %v, want positional error", err)
	}
	if err := run(ctx, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "--mod_root flag must be provided") {
		t.Fatalf("run(no flags) = %v, want --mod_root error", err)
	}
	if err := run(ctx, []string{
		"--mod_root=" + tmpDir,
		"--vindex_url=http://127.0.0.1:8080",
		"--input_log_url=/etc/passwd",
	}, io.Discard); err == nil || !strings.Contains(err.Error(), "scheme must be http, https, or file") {
		t.Fatalf("run(bare input_log_url) = %v, want scheme validation error", err)
	}

	// Verify runGit surfaces git's stderr diagnostic text (e.g. dubious ownership / #69) rather than bare "exit status 128".
	gitRepo := filepath.Join(tmpDir, "repo")
	if err := os.MkdirAll(gitRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	newGitHelper(t, gitRepo)("init")
	if _, err := runGit(ctx, gitRepo, "rev-parse", "--verify", "refs/tags/missing-ref"); err == nil || !strings.Contains(err.Error(), "fatal:") {
		t.Fatalf("runGit stderr not surfaced in error: %v", err)
	}
}

func TestParseLeaf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		idx         uint64
		data        []byte
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "valid leaf",
			idx:         42,
			data:        testExampleLeaf,
			wantVersion: "v0.3.0",
			wantErr:     false,
		},
		{
			name:    "single line",
			idx:     1,
			data:    []byte("golang.org/x/text v0.3.0 h1:hash="),
			wantErr: true,
		},
		{
			name:    "extra trailing line rejected",
			idx:     2,
			data:    []byte("mod1 v0.1.0 h1:hash=\nmod1 v0.1.0/go.mod h1:hash=\nextra line\n"),
			wantErr: true,
		},
		{
			name:    "extra whitespace tokens rejected",
			idx:     3,
			data:    []byte("mod1 extra v0.1.0 h1:hash=\nmod1 extra v0.1.0/go.mod h1:hash=\n"),
			wantErr: true,
		},
		{
			name:    "mismatched module names",
			idx:     4,
			data:    []byte("mod1 v0.1.0 h1:hash=\nmod2 v0.1.0/go.mod h1:hash=\n"),
			wantErr: true,
		},
		{
			name:    "mismatched versions",
			idx:     5,
			data:    []byte("mod1 v0.1.0 h1:hash=\nmod1 v0.2.0/go.mod h1:hash=\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ver, md, err := parseLeaf(tt.idx, tt.data, "")
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLeaf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ver != tt.wantVersion {
					t.Errorf("parseLeaf() version = %q, want %q", ver, tt.wantVersion)
				}
				if md.index != tt.idx {
					t.Errorf("parseLeaf() index = %d, want %d", md.index, tt.idx)
				}
				if md.zipHash != "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=" {
					t.Errorf("parseLeaf() zipHash = %q, want expected", md.zipHash)
				}
				if md.modHash != "h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=" {
					t.Errorf("parseLeaf() modHash = %q, want expected", md.modHash)
				}
			}
		})
	}

	if _, _, err := parseLeaf(42, testExampleLeaf, "other.org/mod"); err == nil {
		t.Fatal("expected parseLeaf to reject leaf with wrong expectedMod")
	}
	if _, _, err := parseLeaf(42, testExampleLeaf, "golang.org/x/text"); err != nil {
		t.Fatalf("expected parseLeaf to accept matching expectedMod, got: %v", err)
	}
}

func TestGetReport_LocalGitRepo(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	repoDir := t.TempDir()
	gitExec := newGitHelper(t, repoDir)

	gitExec("init")
	// Pre-module release v0.0.1 and v2.0.0+incompatible (no go.mod yet)
	if err := os.WriteFile(filepath.Join(repoDir, "hello.go"), []byte("package hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "hello.go")
	gitExec("commit", "-m", "pre-module")
	gitExec("tag", "v0.0.1")
	gitExec("tag", "v2.0.0")
	commitPre := gitExec("rev-parse", "v0.0.1^{commit}")

	// Lightweight tag v0.1.0 with go.mod
	goModContent := []byte("module example.com/hello\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), goModContent, 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "go.mod")
	gitExec("commit", "-m", "add go.mod")
	gitExec("tag", "v0.1.0")
	commitV1 := gitExec("rev-parse", "v0.1.0^{commit}")

	// Annotated tag v0.2.0
	if err := os.WriteFile(filepath.Join(repoDir, "hello.go"), []byte("package hello\n\nconst V = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "hello.go")
	gitExec("commit", "-m", "v0.2.0")
	gitExec("tag", "-a", "v0.2.0", "-m", "annotated release")
	commitV2 := gitExec("rev-parse", "v0.2.0^{commit}")

	wantModHash := mustModHash(t, goModContent)
	wantZipPre := mustZipHash(t, repoDir, "example.com/hello", "v0.0.1", commitPre, "")
	wantZipIncompat := mustZipHash(t, repoDir, "example.com/hello", "v2.0.0+incompatible", commitPre, "")
	wantZipV1 := mustZipHash(t, repoDir, "example.com/hello", "v0.1.0", commitV1, "")
	wantZipV2 := mustZipHash(t, repoDir, "example.com/hello", "v0.2.0", commitV2, "")

	report, err := getReport(ctx, repoDir, func(_ context.Context, modName string) (map[string]modData, error) {
		if modName != "example.com/hello" {
			t.Fatalf("unexpected modName %q", modName)
		}
		return map[string]modData{
			"v0.0.1":              {index: 1, modHash: "h1:synthetic=", zipHash: wantZipPre},
			"v0.1.0":              {index: 10, modHash: wantModHash, zipHash: wantZipV1},
			"v0.2.0":              {index: 20, modHash: wantModHash, zipHash: wantZipV2},
			"v2.0.0+incompatible": {index: 30, modHash: "h1:synthetic=", zipHash: wantZipIncompat},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport failed: %v", err)
	}
	if len(report.versions) != 4 {
		t.Fatalf("len(report.versions) = %d, want 4", len(report.versions))
	}
	if report.versions[0].version != "v0.0.1" || report.versions[0].gitModHash != "" || report.versions[0].gitZipHash != wantZipPre {
		t.Fatalf("unexpected pre-module v0.0.1 report: %+v", report.versions[0])
	}
	if report.versions[1].gitModHash != wantModHash || report.versions[1].gitZipHash != wantZipV1 {
		t.Fatalf("v0.1.0 hash mismatch: %+v", report.versions[1])
	}
	if report.versions[2].gitModHash != wantModHash || report.versions[2].gitZipHash != wantZipV2 {
		t.Fatalf("v0.2.0 annotated tag hash mismatch: %+v", report.versions[2])
	}
	if report.versions[3].version != "v2.0.0+incompatible" || report.versions[3].gitZipHash != wantZipIncompat {
		t.Fatalf("v2.0.0+incompatible hash mismatch: %+v", report.versions[3])
	}

	// Local git tag missing from SumDB must be surfaced with sumFound == false.
	gitExec("tag", "v0.3.0")
	reportMissing, err := getReport(ctx, repoDir, func(_ context.Context, _ string) (map[string]modData, error) {
		return map[string]modData{
			"v0.0.1":              {index: 1, modHash: "h1:synthetic=", zipHash: wantZipPre},
			"v0.1.0":              {index: 10, modHash: wantModHash, zipHash: wantZipV1},
			"v0.2.0":              {index: 20, modHash: wantModHash, zipHash: wantZipV2},
			"v2.0.0+incompatible": {index: 30, modHash: "h1:synthetic=", zipHash: wantZipIncompat},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport with missing SumDB tag failed: %v", err)
	}
	if len(reportMissing.versions) != 5 || reportMissing.versions[3].version != "v0.3.0" || reportMissing.versions[3].sumFound {
		t.Fatalf("expected v0.3.0 with sumFound=false, got: %+v", reportMissing.versions)
	}
}

func TestGetReport_MajorSubdirV2AndMonorepoSubmodule(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	repoDir := t.TempDir()
	gitExec := newGitHelper(t, repoDir)

	gitExec("init")

	// 0. Pre-module v2.0.0 tag before any go.mod existed (belongs to root module as v2.0.0+incompatible, NOT /v2!)
	if err := os.WriteFile(filepath.Join(repoDir, "multi.go"), []byte("package multi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "multi.go")
	gitExec("commit", "-m", "pre-module v2.0.0")
	gitExec("tag", "v2.0.0")
	preModCommit := gitExec("rev-parse", "HEAD")

	// 1. Root v1 module (v1.0.0)
	v1Mod := []byte("module example.com/multi\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), v1Mod, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Major subdirectory v2/go.mod (module example.com/multi/v2, tagged v2.1.0)
	v2Dir := filepath.Join(repoDir, "v2")
	if err := os.MkdirAll(v2Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	v2Mod := []byte("module example.com/multi/v2\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(v2Dir, "go.mod"), v2Mod, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v2Dir, "multi.go"), []byte("package multi\n\nconst Major = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Monorepo submodule tools/go.mod (module example.com/multi/tools, tagged tools/v0.4.0)
	subDir := filepath.Join(repoDir, "tools")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	subMod := []byte("module example.com/multi/tools\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(subDir, "go.mod"), subMod, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "tools.go"), []byte("package tools\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	gitExec("add", ".")
	gitExec("commit", "-m", "init multi-module repo")
	gitExec("tag", "v1.0.0")
	gitExec("tag", "v2.1.0")
	gitExec("tag", "tools/v0.4.0")
	headCommit := gitExec("rev-parse", "HEAD")

	// Verify v2/go.mod: must match v2.1.0 (NOT v1.0.0 or tools/v0.4.0!)
	wantV2Mod := mustModHash(t, v2Mod)
	wantV2Zip := mustZipHash(t, repoDir, "example.com/multi/v2", "v2.1.0", headCommit, "v2")
	repV2, err := getReport(ctx, v2Dir, func(_ context.Context, modName string) (map[string]modData, error) {
		if modName != "example.com/multi/v2" {
			t.Fatalf("unexpected v2 modName %q", modName)
		}
		return map[string]modData{
			"v2.1.0": {index: 100, modHash: wantV2Mod, zipHash: wantV2Zip},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport(v2) failed: %v", err)
	}
	if len(repV2.versions) != 1 || repV2.versions[0].version != "v2.1.0" || !repV2.versions[0].sumFound ||
		repV2.versions[0].gitModHash != wantV2Mod || repV2.versions[0].gitZipHash != wantV2Zip {
		t.Fatalf("unexpected v2 report: %+v", repV2.versions)
	}

	// Verify root v1 go.mod: must include pre-module v2.0.0+incompatible and exclude v2.1.0 (which has v2/go.mod!) and tools/v0.4.0!
	wantV1Mod := mustModHash(t, v1Mod)
	wantV1Zip := mustZipHash(t, repoDir, "example.com/multi", "v1.0.0", headCommit, "")
	wantPreV2Zip := mustZipHash(t, repoDir, "example.com/multi", "v2.0.0+incompatible", preModCommit, "")
	repV1, err := getReport(ctx, repoDir, func(_ context.Context, modName string) (map[string]modData, error) {
		if modName != "example.com/multi" {
			t.Fatalf("unexpected v1 modName %q", modName)
		}
		return map[string]modData{
			"v1.0.0":              {index: 50, modHash: wantV1Mod, zipHash: wantV1Zip},
			"v2.0.0+incompatible": {index: 10, modHash: "h1:synthetic=", zipHash: wantPreV2Zip},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport(v1) failed: %v", err)
	}
	if len(repV1.versions) != 2 || repV1.versions[0].version != "v1.0.0" || repV1.versions[1].version != "v2.0.0+incompatible" {
		t.Fatalf("unexpected v1 report (should include v1.0.0 + v2.0.0+incompatible and exclude v2.1.0/tools): %+v", repV1.versions)
	}

	// Verify monorepo subdirectory tools/go.mod: must resolve tag tools/v0.4.0 cleanly
	wantSubMod := mustModHash(t, subMod)
	wantSubZip := mustZipHash(t, repoDir, "example.com/multi/tools", "v0.4.0", headCommit, "tools")
	repSub, err := getReport(ctx, subDir, func(_ context.Context, modName string) (map[string]modData, error) {
		if modName != "example.com/multi/tools" {
			t.Fatalf("unexpected submodule modName %q", modName)
		}
		return map[string]modData{
			"v0.4.0": {index: 75, modHash: wantSubMod, zipHash: wantSubZip},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport(tools) failed: %v", err)
	}
	if len(repSub.versions) != 1 || repSub.versions[0].version != "v0.4.0" ||
		repSub.versions[0].gitModHash != wantSubMod || repSub.versions[0].gitZipHash != wantSubZip {
		t.Fatalf("unexpected tools report: %+v", repSub.versions)
	}
}

func TestQueryIndex_IntegrationAndMaxFromHorizon(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tempDir := t.TempDir()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(input) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "sumdb.vindex.local")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(output) failed: %v", err)
	}

	inLogDir := filepath.Join(tempDir, "inputlog")
	inLog, err := tree.NewPOSIXOutputLog(ctx, inLogDir, inSigner, tree.WithOrigin("sum.golang.org"))
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog(input) failed: %v", err)
	}
	defer func() { _ = inLog.Close() }()

	for i, leaf := range [][]byte{testExampleLeaf, testExampleLeaf2} {
		if _, _, err := inLog.Append(ctx, leaf); err != nil {
			t.Fatalf("inLog.Append(%d) failed: %v", i, err)
		}
	}

	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("NewSigner(out) failed: %v", err)
	}
	inPol, err := client.SingleKeyPolicy("sum.golang.org", inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(in) failed: %v", err)
	}

	engine, err := vindex.New(
		vindex.StorageConfig{
			DBPath:       filepath.Join(tempDir, "pebble"),
			MPTDir:       ":memory:",
			TileCacheDir: filepath.Join(tempDir, "tilecache"),
			OutputLogDir: filepath.Join(tempDir, "outputlog"),
		},
		outSigner,
		vindex.WithInputLog("file://"+inLogDir, inPol, wasmhosttest.Host()),
		vindex.WithFrom(1),
		vindex.WithTuning(vindex.TuningOptions{ChunkSize: 16}),
	)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	outPolicy, err := client.SingleKeyPolicy("sumdb.vindex.local", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		OutputLogPolicy:        outPolicy,
		ExpectedInputLogOrigin: "sum.golang.org",
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	inPolicy, err := wire.BuildPolicy("sum.golang.org", inVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(input) failed: %v", err)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	parsedFileURL, err := parseInputLogURL("file://" + inLogDir)
	if err != nil {
		t.Fatal(err)
	}

	// Default maxFrom=0 must reject From=1 suffix index so omitted older releases cannot pass silently.
	if _, err := queryIndex(ctx, httpClient, cli, parsedFileURL, "sum.golang.org", inPolicy, "golang.org/x/text", 0); err == nil {
		t.Fatal("expected queryIndex with maxFrom=0 to reject From=1 suffix index")
	}

	// Allowing maxFrom=1 succeeds and verifies Input Log checkpoint consistency + leaf 1 dereference.
	versions, err := queryIndex(ctx, httpClient, cli, parsedFileURL, "sum.golang.org", inPolicy, "golang.org/x/text", 1)
	if err != nil {
		t.Fatalf("queryIndex(maxFrom=1) failed: %v", err)
	}
	if len(versions) != 1 || versions["v0.3.1"].index != 1 {
		t.Fatalf("expected [v0.3.1 @ 1], got %v", versions)
	}

	// Input Log checkpoint behind VIndex committed InputSize (e.g. signed size 0 < 2) MUST fail closed.
	staleCP := log.Checkpoint{Origin: "sum.golang.org", Size: 0, Hash: rfc6962.DefaultHasher.EmptyRoot()}
	signedStale, err := note.Sign(&note.Note{Text: string(staleCP.Marshal())}, inSigner)
	if err != nil {
		t.Fatal(err)
	}
	staleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/checkpoint") {
			_, _ = w.Write(signedStale)
			return
		}
		http.FileServer(http.Dir(inLogDir)).ServeHTTP(w, r)
	}))
	defer staleSrv.Close()
	parsedStaleURL, err := parseInputLogURL(staleSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queryIndex(ctx, httpClient, cli, parsedStaleURL, "sum.golang.org", inPolicy, "golang.org/x/text", 1); err == nil || !strings.Contains(err.Error(), "exceeds signed Input Log checkpoint size 0") {
		t.Fatalf("expected error when VIndex InputSize exceeds signed Input Log checkpoint size, got: %v", err)
	}
}
