// Copyright 2025 Google LLC. All Rights Reserved.
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

// sumdbverify defines a binary that uses the Go Checksum Verifiable Index
// to look up versions for a given Go module, and compares these entries with
// the local git tags.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/zip"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	baseURL      = flag.String("base_url", "", "The base URL of the server hosting the logs and vindex.")
	outLogPubKey = flag.String("out_log_pub_key", "", "The public key to use to verify the output log checkpoint.")
	modRoot      = flag.String("mod_root", "", "The path to a go module checked out locally via git.")
)

var (
	// Example leaf:
	// golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
	// golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
	//
	line0RE = regexp.MustCompile(`(.*) (.*) (h1:.*)`)
	line1RE = regexp.MustCompile(`(.*) (.*)/go.mod (h1:.*)`)
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if err := run(context.Background()); err != nil {
		klog.Exitf("run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *modRoot == "" {
		return errors.New("mod_root flag must be provided")
	}

	var sumFetcher func(ctx context.Context, modName string) (map[string]modData, error)
	if *baseURL == "" {
		klog.Warningf("--base_url is not provided. Using NON-VERIFIABLE lookup to source SumDB data.")

		// This constructs the map non-verifiably by calling similar URLs to these:
		// 1) https://proxy.golang.org/github.com/transparency-dev/tessera/@v/list
		// 2) https://sum.golang.org/lookup/github.com/transparency-dev/tessera@v1.0.0
		sumFetcher = func(ctx context.Context, modName string) (map[string]modData, error) {
			result := make(map[string]modData)
			resp, err := http.Get(fmt.Sprintf("https://proxy.golang.org/%s/@v/list", modName))
			if err != nil {
				return nil, fmt.Errorf("failed to get module listing: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to get module listing: %v", err)
			}
			for v := range strings.Lines(string(body)) {
				v = strings.TrimSpace(v)
				resp, err = http.Get(fmt.Sprintf("https://sum.golang.org/lookup/%s@%s", modName, v))
				if err != nil {
					return nil, fmt.Errorf("failed to get version info: %v", err)
				}
				body, err = io.ReadAll(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to get version info: %v", err)
				}
				lines := bytes.Split(body, []byte{'\n'})
				idx, err := strconv.ParseInt(string(lines[0]), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("failed to parse index: %v", err)
				}
				leaf := append(append(append(lines[1], byte('\n')), lines[2]...), byte('\n'))
				v2, md, err := parseLeaf(uint64(idx), leaf)
				if err != nil {
					return nil, fmt.Errorf("failed to parse leaf: %v", err)
				}
				if v != v2 {
					return nil, fmt.Errorf("performed lookup for %s@%s but got version %s", modName, v, v2)
				}
				result[v] = md
			}
			return result, nil
		}

	} else {
		if *outLogPubKey == "" {
			return errors.New("out_log_pub_key flag must be provided if --base_url is provided")
		}
		sumFetcher = func(ctx context.Context, modName string) (map[string]modData, error) {
			vic := newVIndexClientFromFlags()
			return queryIndex(ctx, vic, modName)
		}
	}

	report, reportErr := getReport(ctx, *modRoot, sumFetcher)
	if reportErr != nil && len(report.versions) == 0 {
		return fmt.Errorf("failed to compile report: %v", reportErr)
	}

	fmt.Printf("%s (./%s)\n", report.modName, report.modPath)

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "VERSION\tINDEX\tFOUND\tgo.mod\tzip\t"); err != nil {
		return fmt.Errorf("failed to output report: %v", err)
	}
	for _, v := range report.versions {
		var sumIndex string
		if v.sumFound {
			sumIndex = strconv.FormatUint(v.sumIndex, 10)
		} else {
			sumIndex = "--"
		}

		gitHash := "✅"
		if v.gitCommitHash == nil {
			gitHash = "❌"
		}

		goMod := "✅"
		if v.gitCommitHash == nil || len(v.gitModHash) == 0 {
			goMod = "⚠️"
		} else if v.gitModHash != v.sumModHash {
			goMod = "❌"
		}

		goZip := "✅"
		if v.gitCommitHash == nil || len(v.gitModHash) == 0 {
			goZip = "⚠️"
		} else if v.gitZipHash != v.sumZipHash {
			klog.Warningf("zip: git != sum: %s != %s", v.gitZipHash, v.sumZipHash)
			goZip = "❌"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", v.version, sumIndex, gitHash, goMod, goZip); err != nil {
			return fmt.Errorf("failed to output report: %v", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush report to stdout: %v", err)
	}

	return reportErr
}

func findGoMod(modRoot string) (string, error) {
	goModPath := "go.mod"
	if s, err := os.Stat(filepath.Join(modRoot, goModPath)); err == nil && !s.IsDir() {
		return goModPath, nil
	}

	err := filepath.WalkDir(modRoot, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && d.Name() == "go.mod" {
			relPath, err := filepath.Rel(modRoot, path)
			if err != nil {
				return err
			}
			goModPath = relPath
			return os.ErrExist
		}
		return nil
	})
	if errors.Is(err, os.ErrExist) {
		return goModPath, nil
	}

	return "", fmt.Errorf("failed to read go.mod file: %v", err)
}

func getReport(ctx context.Context, modRoot string, sumFetcher func(context.Context, string) (map[string]modData, error)) (diffReport, error) {
	if s, err := os.Stat(modRoot); err != nil || !s.IsDir() {
		return diffReport{}, errors.New("mod_root flag must be a directory")
	}
	goModPath, err := findGoMod(modRoot)
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to find go.mod file in %s", modRoot)
	}
	modPathBytes, err := os.ReadFile(filepath.Join(modRoot, goModPath))
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to read go.mod file: %v", err)
	}
	modName := modfile.ModulePath(modPathBytes)
	if modName == "" {
		return diffReport{}, fmt.Errorf("failed to parse go.mod file: %v", err)
	}

	report := diffReport{
		modName:  modName,
		modPath:  goModPath,
		versions: make([]versionReport, 0),
	}

	repo, err := git.PlainOpen(modRoot)
	if err != nil {
		return report, fmt.Errorf("directory at mod_root %q cannot be opened as git repo: %v", modRoot, err)
	}
	eg, egctx := errgroup.WithContext(ctx)
	var versions map[string]modData
	var tags map[string]struct{}

	eg.Go(func() error {
		var err error
		versions, err = sumFetcher(egctx, modName)
		return err
	})
	eg.Go(func() error {
		refIter, err := repo.References()
		if err != nil {
			return fmt.Errorf("failed to list references: %v", err)
		}

		tags = make(map[string]struct{})
		if err := refIter.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().IsTag() {
				tagName := ref.Name().Short()
				tags[tagName] = struct{}{}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to list tags: %v", err)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return report, err
	}

	// Create a sorted slice of versions
	sv := make([]string, 0, len(versions))
	for v := range versions {
		sv = append(sv, v)
	}
	semver.Sort(sv)

	vErrors := make([]error, 0)
	for _, v := range sv {
		sumHashes := versions[v]

		vr, err := reportVersion(ctx, modRoot, goModPath, modName, repo, v)
		if err != nil {
			vErrors = append(vErrors, fmt.Errorf("failed to get report for version %q: %v", v, err))
		}
		vr.sumFound = true
		vr.sumModHash = sumHashes.modHash
		vr.sumZipHash = sumHashes.zipHash
		vr.sumIndex = sumHashes.index
		report.versions = append(report.versions, vr)

		if vr.gitCommitHash != nil {
			delete(tags, v)
		}
	}

	// TODO(mhutchinson): Include information on tags in git that aren't in SumDB
	// if len(tags) > 0 {
	// 	for t := range tags {
	// 		report.versions = append(report.versions, versionReport{
	// 			version:  t,
	// 			sumFound: false,
	//          // also include git info here
	// 		})
	// 	}
	// }
	return report, errors.Join(vErrors...)
}

func reportVersion(ctx context.Context, modRoot string, goModPath string, modName string, repo *git.Repository, v string) (versionReport, error) {
	report := versionReport{
		version: v,
	}

	// Find the commit this tag points to.
	ref := plumbing.NewTagReferenceName(v)
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return report, fmt.Errorf("failed to resolve tag '%s' to a commit: %v", ref, err)
	}

	// Update report to include the sha1 commit hash the tag points to.
	report.gitCommitHash = hash[:]

	// Find the go.mod file in this commit.
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return report, fmt.Errorf("failed to get commit object: %v", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return report, fmt.Errorf("failed to get commit tree: %v", err)
	}

	// There is some gnarliness here:
	//  - the path passed in must only be "go.mod" as that is used in the hash construction
	//  - the path _may_ be nested, in reality
	// The workaround is to pass in "go.mod" and then ignore it in the function, and just use
	// the real path in the git directory when looking it up.
	hs, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		modFile, err := tree.File(goModPath)
		if err != nil {
			return nil, err
		}

		blob, err := repo.BlobObject(modFile.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to get blob object: %v", err)
		}
		return blob.Reader()
	})
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			// This isn't necessarily an error: old versions didn't have go.mod files
			return report, nil
		}
		return report, fmt.Errorf("failed to calculate file hash: %v", err)
	}

	// Update the report with the mod hash, and then calculate the zip hash.
	report.gitModHash = hs
	f, err := os.CreateTemp("", "goModZip")
	if err != nil {
		return report, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			klog.Warningf("failed to remove temporary file: %v", err)
		}
	}()
	modVer := module.Version{
		Path:    modName,
		Version: v,
	}
	subdir := filepath.Dir(goModPath)
	if subdir == "." {
		subdir = ""
	}
	if err := zip.CreateFromVCS(f, modVer, modRoot, hash.String(), subdir); err != nil {
		return report, fmt.Errorf("failed to create zip file: %v", err)
	}
	report.gitZipHash, err = dirhash.HashZip(f.Name(), dirhash.Hash1)
	if err != nil {
		return report, fmt.Errorf("failed to hash zip file: %v", err)
	}

	return report, nil
}

type diffReport struct {
	modName  string
	modPath  string
	versions []versionReport
}

type versionReport struct {
	version string

	// These fields are written in-order, as further info becomes available.
	// If no commit hash is present, then the version tag was not found in git.
	gitCommitHash []byte
	gitModHash    string
	gitZipHash    string

	// If sumFound is not set, then no entry was found in SumDB so fields below
	// should not be referenced.
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

func queryIndex(ctx context.Context, vic *client.VIndexClient, modName string) (map[string]modData, error) {
	idxes, inCp, err := vic.Lookup(ctx, modName)
	if err != nil {
		return nil, fmt.Errorf("failed to look up key: %v", err)
	}

	versions := make(map[string]modData, len(idxes))

	lr := newInputLogClientFromFlags()
	klog.V(1).Infof("Dereferencing %d pointers", len(idxes))
	for leaf, err := range lr.Dereference(ctx, inCp, idxes) {
		if err != nil {
			return nil, fmt.Errorf("failed to get leaf at index %d: %v", leaf.Index, err)
		}
		version, data, err := parseLeaf(leaf.Index, leaf.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf at index %d: %v", leaf.Index, err)
		}
		if prev, found := versions[version]; found {
			return nil, fmt.Errorf("conflicting versions for version %q found!\n%v\n%v", version, prev, data)
		}
		versions[version] = data
	}
	return versions, nil
}

// parseLeaf extracts the version string and the hashes from the raw leaf data.
func parseLeaf(idx uint64, data []byte) (string, modData, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return "", modData{}, fmt.Errorf("expected 2 lines but got %d", len(lines))
	}

	line0Parts := line0RE.FindStringSubmatch(lines[0])
	line0Module, line0Version, zipHashB64 := line0Parts[1], line0Parts[2], line0Parts[3]

	line1Parts := line1RE.FindStringSubmatch(lines[1])
	line1Module, line1Version, modHashB64 := line1Parts[1], line1Parts[2], line1Parts[3]

	if line0Module != line1Module {
		return "", modData{}, fmt.Errorf("mismatched module names: (%s, %s)", line0Module, line1Module)
	}
	if line0Version != line1Version {
		return "", modData{}, fmt.Errorf("mismatched version names: (%s, %s)", line0Version, line1Version)
	}

	return line0Version, modData{
		index:   idx,
		zipHash: zipHashB64,
		modHash: modHashB64,
	}, nil
}

func newVIndexClientFromFlags() *client.VIndexClient {
	outV, err := note.NewVerifier(*outLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct VIndex verifier: %v", err)
	}
	u, err := url.JoinPath(*baseURL, "/vindex/")
	if err != nil {
		klog.Exitf("failed to construct VIndex URL: %v", err)
	}
	c, err := client.NewVIndexClient(u, outV)
	if err != nil {
		klog.Exitf("failed to construct VIndex Client: %v", err)
	}
	return c
}

func newInputLogClientFromFlags() *client.InputLogClient {
	v, err := note.NewVerifier("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8")
	if err != nil {
		klog.Exitf("failed to construct Input Log verifier: %v", err)
	}
	u, err := url.JoinPath(*baseURL, "/inputlog/")
	if err != nil {
		klog.Exitf("failed to construct Input Log URL: %v", err)
	}
	origin := "go.sum database tree"
	c, err := client.NewInputLogClient(u, origin, v, http.DefaultClient)
	if err != nil {
		klog.Exitf("failed to construct Input Log client: %v", err)
	}
	return c
}
