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

// sumdb brings up a verifiable index for the Go SumDB.
// This requires a proxy to be running to bridge to a tlog-tiles API.
// See the README for usage details.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/sumdb"
	"github.com/transparency-dev/incubator/vindex"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	outputLogPrivKeyFile = flag.String("output_log_private_key", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the demo. This will create subdirectories for the Output Log, and allocate space to store the verifiable map persistence.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on")
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		klog.Exitf("Run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	// Set up storage for the input log, index, and output log.
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}
	inputLogDir := path.Join(*storageDir, "inputlog")
	outputLogDir := path.Join(*storageDir, "outputlog")
	mapRoot := path.Join(*storageDir, "vindex")

	if err := os.MkdirAll(inputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create input log directory: %v", err)
	}
	if err := os.MkdirAll(outputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output log directory: %v", err)
	}
	if err := os.MkdirAll(mapRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create vindex directory: %v", err)
	}

	sumV, err := note.NewVerifier("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8")
	if err != nil {
		return err
	}
	sumUrl, err := url.Parse(fmt.Sprintf("http://%s/inputlog/", *listen))
	if err != nil {
		return err
	}
	inputLog, err := vindex.NewTiledInputLog(sumUrl, sumV, vindex.InputLogOpts{
		HttpClient: http.DefaultClient,
		Origin:     "go.sum database tree",
	})
	if err != nil {
		return err
	}
	sumProxy := sumdb.NewProxy(sumdb.ProxyOpts{
		PathPrefix: "/inputlog/",
	})

	outputLog, outputCloser := outputLogOrDie(ctx, outputLogDir)
	defer outputCloser()

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFnOrDie(), outputLog, mapRoot, vindex.Options{})
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}

	// Run a web server to serve the input log, index, and output log.
	go runWebServer(sumProxy, vi, outputLogDir)

	// Keeps the map synced with the latest published input log state.
	go maintainMap(ctx, vi)

	<-ctx.Done()
	return nil
}

// outputLogOrDie returns an output log using a POSIX log in the given directory.
func outputLogOrDie(ctx context.Context, outputLogDir string) (log vindex.OutputLog, closer func()) {
	s, v := getOutputLogSignerVerifierOrDie()

	l, c, err := vindex.NewOutputLog(ctx, outputLogDir, s, v)
	if err != nil {
		klog.Exit(err)
	}
	return l, c
}

// maintainMap reads entries from the log and sync them to the vindex.
func maintainMap(ctx context.Context, vi *vindex.VerifiableIndex) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		if err := vi.Update(ctx); err != nil {
			klog.Warning(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runWebServer(inLog *httputil.ReverseProxy, vi *vindex.VerifiableIndex, outLogDir string) {
	web := NewServer(vi.Lookup)

	olfs := http.FileServer(http.Dir(outLogDir))
	r := mux.NewRouter()
	r.PathPrefix("/inputlog/").Handler(inLog)
	r.PathPrefix("/outputlog/").Handler(http.StripPrefix("/outputlog/", olfs))
	web.registerHandlers(r)
	hServer := &http.Server{
		Addr:    *listen,
		Handler: r,
	}
	go func() {
		if err := hServer.ListenAndServe(); err != http.ErrServerClosed {
			klog.Warning(err)
		}
	}()
	klog.Infof("Started HTTP server listening on %s", *listen)
}

// Read output log private key from file or environment variable and generate the
// note Signer and Verifier pair for it.
func getOutputLogSignerVerifierOrDie() (note.Signer, note.Verifier) {
	var privKey string
	var err error
	if len(*outputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*outputLogPrivKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
		}
	} else {
		privKey = os.Getenv("OUTPUT_LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			klog.Exit("Supply private key file path using --output_log_private_key or set OUTPUT_LOG_PRIVATE_KEY environment variable")
		}
	}
	s, v, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		klog.Exitf("Failed to get signer/verifier: %v", err)
	}
	return s, v
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

func mapFnOrDie() vindex.MapFn {
	mapFn := func(data []byte) [][32]byte {
		lines := strings.Split(string(data), "\n")
		if len(lines) < 2 {
			panic(fmt.Errorf("expected 2 lines but got %d", len(lines)))
		}

		line0Parts := line0RE.FindStringSubmatch(lines[0])
		line0Module, line0Version := line0Parts[1], line0Parts[2]

		line1Parts := line1RE.FindStringSubmatch(lines[1])
		line1Module, line1Version := line1Parts[1], line1Parts[2]

		if line0Module != line1Module {
			klog.Errorf("mismatched module names: (%s, %s)", line0Module, line1Module)
		}
		if line0Version != line1Version {
			klog.Errorf("mismatched version names: (%s, %s)", line0Version, line0Version)
		}
		if module.IsPseudoVersion(line0Version) {
			// Drop any emphemeral builds
			return nil
		}

		klog.V(2).Infof("MapFn found: Module: %s:\t%s", line0Module, line0Version)

		return [][32]byte{sha256.Sum256([]byte(line0Module))}
	}
	return mapFn
}
