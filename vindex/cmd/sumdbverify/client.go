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
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/note"
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
	line0RE = regexp.MustCompile(`(.*) (.*) h1:(.*)`)
	line1RE = regexp.MustCompile(`(.*) (.*)/go.mod h1:(.*)`)
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if err := run(context.Background()); err != nil {
		klog.Exitf("run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *baseURL == "" {
		return errors.New("base_url flag must be provided")
	}
	if *outLogPubKey == "" {
		return errors.New("out_log_pub_key flag must be provided")
	}
	if *modRoot == "" {
		return errors.New("mod_root flag must be provided")
	}
	if s, err := os.Stat(*modRoot); err != nil || !s.IsDir() {
		return errors.New("mod_root flag must be a directory")
	}
	modPathBytes, err := os.ReadFile(filepath.Join(*modRoot, "go.mod"))
	if err != nil {
		return fmt.Errorf("failed to read go.mod file: %v", err)
	}
	modPath, err := modfile.Parse("go.mod", modPathBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to parse go.mod file: %v", err)
	}
	modName := modPath.Module.Mod.Path

	eg, egctx := errgroup.WithContext(ctx)
	var versions map[string]modData
	var tags map[string]struct{}

	eg.Go(func() error {
		// This function gets all version info from the verifiable index.
		vic := newVIndexClientFromFlags()

		versions, err = queryIndex(egctx, vic, modName)
		if err != nil {
			return fmt.Errorf("error querying index: %v", err)
		}
		return nil
	})
	eg.Go(func() error {
		// This function gets all tags from the local git checkout.
		rawTags, err := queryTags(egctx, *modRoot)
		if err != nil {
			return fmt.Errorf("error enumerating git tags: %v", err)
		}
		tags = make(map[string]struct{}, len(rawTags))
		for _, t := range rawTags {
			tags[t] = struct{}{}
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return err
	}

	// Create a sorted slice of versions
	sv := make([]string, 0, len(versions))
	for v := range versions {
		sv = append(sv, v)
	}
	semver.Sort(sv)

	fmt.Println(modName)
	for _, v := range sv {
		d := versions[v]
		presence := "✅ found in git tags"
		if _, found := tags[v]; !found {
			presence = "❌ missing from git tags"
		}

		fmt.Printf("%s found at index %d: %s\n", v, d.index, presence)
		delete(tags, v)
	}

	if len(tags) > 0 {
		fmt.Println("----------")
		fmt.Println("> INFO: The tagged versions below were never downloaded via the Module Proxy")
		for t := range tags {
			fmt.Printf("%s found locally but missing from SumDB\n", t)
		}
	}
	return nil
}

type modData struct {
	index   uint64
	zipHash []byte
	modHash []byte
}

func queryTags(ctx context.Context, modRoot string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "tag")
	cmd.Dir = modRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run git tag: %w", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return []string{}, nil
	}
	tags := strings.Split(trimmed, "\n")
	return tags, nil
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
		panic(fmt.Errorf("expected 2 lines but got %d", len(lines)))
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

	zipHash, err := base64.StdEncoding.DecodeString(zipHashB64)
	if err != nil {
		return "", modData{}, fmt.Errorf("failed to decode hash %q: %v", zipHashB64, err)
	}
	modHash, err := base64.StdEncoding.DecodeString(modHashB64)
	if err != nil {
		return "", modData{}, fmt.Errorf("failed to decode hash %q: %v", modHashB64, err)
	}
	return line0Version, modData{
		index:   idx,
		zipHash: zipHash,
		modHash: modHash,
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
