// Copyright 2026 Google LLC. All Rights Reserved.
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

// ct is a binary that indexes a static CT log (the input log) into a verifiable
// index, and publishes the index checkpoints to a Tessera POSIX log (the output log).
// A web server is hosted that allows lookups in the index to be performed.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"iter"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/publicsuffix"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"github.com/gorilla/mux"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/web"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"k8s.io/klog/v2"
)

var (
	inputLogUrl        = flag.String("input_log_url", "", "Base URL of the static CT log to index. This must be the monitoring URL, not the submission URL.")
	origin             = flag.String("origin", "", "Origin of the log to check")
	pubKey             = flag.String("public_key", "", "The log's public key in base64 encoded DER format")
	userAgentInfo      = flag.String("user_agent_info", "", "Optional string to append to the user agent (e.g. email address for Sunlight logs)")
	persistentCacheDir = flag.String("persistent_cache_dir", "", "Optional location of a directory to cache Input Log tiles")
	persistIndex       = flag.Bool("persist_index", true, "Set to false to use a memory-based implementation of the verifiable index.")

	outputLogPrivKeyFile = flag.String("output_log_private_key", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the demo. This will create subdirectories for the Input Log, Output Log, and allocate space to store the verifiable map persistence.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on")
)

const (
	userAgent = "TrustFabric VerifiableIndex"
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
	if *inputLogUrl == "" {
		return errors.New("input_log_url must be set")
	}
	if *origin == "" {
		return errors.New("origin must be set")
	}
	if *pubKey == "" {
		return errors.New("public_key must be set")
	}

	outputLogDir := path.Join(*storageDir, "outputlog")
	mapRoot := path.Join(*storageDir, "vindex")

	if err := os.MkdirAll(outputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output log directory: %v", err)
	}
	if err := os.MkdirAll(mapRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create vindex directory: %v", err)
	}

	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("failed to create prometheus exporter: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.Shutdown(shutdownCtx); err != nil {
			klog.Errorf("failed to shutdown meter provider: %v", err)
		}
	}()

	outputLog, outputCloser, err := newOutputLogFromFlags(ctx, outputLogDir)
	if err != nil {
		return err
	}
	defer outputCloser(ctx)

	inputLog, err := newStaticCTInputLogFromFlags()
	if err != nil {
		return err
	}

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, mapRoot, vindex.Options{
		PersistIndex:  *persistIndex,
		MeterProvider: provider,
	})
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}
	klog.Info("Created verifiable index")

	// Keeps the map synced with the latest published input log state.
	go maintainMap(ctx, vi)

	// Run a web server to serve the input log, index, and output log.
	go runWebServer(vi, outputLogDir)
	<-ctx.Done()
	return nil
}

func cutEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	// This implementation is terribly inefficient, parsing the whole entry just
	// to re-serialize and throw it away. If this function shows up in profiles,
	// let me know and I'll improve it.
	e, rest, err := sunlight.ReadTileLeaf(tile)
	if err != nil {
		return nil, tlog.Hash{}, nil, err
	}
	rh = tlog.RecordHash(e.MerkleTreeLeaf())
	entry = tile[:len(tile)-len(rest)]
	return entry, rh, rest, nil
}

func newStaticCTInputLogFromFlags() (*staticCTInputLog, error) {
	ua := userAgent
	if *userAgentInfo != "" {
		ua = fmt.Sprintf("%s (%s)", userAgent, *userAgentInfo)
	}
	fetcher, err := torchwood.NewTileFetcher(*inputLogUrl,
		torchwood.WithTilePath(sunlight.TilePath),
		torchwood.WithUserAgent(ua))
	if err != nil {
		return nil, fmt.Errorf("failed to create tile fetcher: %w", err)
	}
	var tileReader torchwood.TileReader = fetcher
	if *persistentCacheDir != "" {
		tileReader, err = torchwood.NewPermanentCache(fetcher, *persistentCacheDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create permanent cache: %w", err)
		}
	}
	client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		return nil, fmt.Errorf("failed to create torchwood client: %w", err)
	}
	v, err := verifierFromFlags()
	if err != nil {
		return nil, err
	}
	return &staticCTInputLog{
		c: client,
		f: fetcher,
		v: v,
	}, nil
}

type staticCTInputLog struct {
	c *torchwood.Client
	f *torchwood.TileFetcher
	v note.Verifier

	lastCheckpoint log.Checkpoint
}

func (l *staticCTInputLog) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	return l.f.ReadEndpoint(ctx, "checkpoint")
}

// Parse unmarshals and verifies a checkpoint obtained from GetCheckpoint.
func (l *staticCTInputLog) Parse(checkpoint []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(checkpoint, l.v.Name(), l.v)
	if err != nil {
		return nil, err
	}
	l.lastCheckpoint = *cp
	return cp, err
}

// Leaves returns all the leaves in the range [start, end), outputting them via
// the returned iterator.
func (l *staticCTInputLog) Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	tree := tlog.Tree{
		N:    int64(end),
		Hash: tlog.Hash(l.lastCheckpoint.Hash),
	}
	return func(yield func([]byte, error) bool) {
		for _, entry := range l.c.Entries(ctx, tree, int64(start)) {
			e, _, err := sunlight.ReadTileLeaf(entry)
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}
			if !yield(e.MerkleTreeLeaf(), nil) {
				return
			}
		}
		if err := l.c.Err(); err != nil {
			yield(nil, l.c.Err())
		}
	}
}

func newOutputLogFromFlags(ctx context.Context, outputLogDir string) (vindex.OutputLog, func(context.Context), error) {
	s, v, err := getOutputLogSignerVerifier()
	if err != nil {
		return nil, nil, err
	}

	l, c, err := vindex.NewOutputLog(ctx, outputLogDir, s, v, vindex.OutputLogOpts{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output log: %w", err)
	}
	return l, c, nil
}

func verifierFromFlags() (note.Verifier, error) {
	if *origin == "" {
		return nil, errors.New("origin must be set")
	}
	if *pubKey == "" {
		return nil, errors.New("public_key must be set")
	}
	derBytes, err := base64.StdEncoding.DecodeString(*pubKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	verifierKey, err := fnote.RFC6962VerifierString(*origin, pub)
	if err != nil {
		return nil, fmt.Errorf("error creating RFC6962 verifier string: %w", err)
	}
	logSigV, err := fnote.NewVerifier(verifierKey)
	if err != nil {
		return nil, fmt.Errorf("error creating verifier: %w", err)
	}

	klog.Infof("Using verifier string: %v", verifierKey)

	return logSigV, nil
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

func runWebServer(vi *vindex.VerifiableIndex, outLogDir string) {
	srv := web.NewServer(vi.Lookup)

	olfs := http.FileServer(http.Dir(outLogDir))
	r := mux.NewRouter()
	r.PathPrefix("/outputlog/").Handler(http.StripPrefix("/outputlog/", olfs))
	srv.RegisterHandlers(r)
	hServer := &http.Server{
		Addr:    *listen,
		Handler: r,
	}
	go func() {
		if err := hServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Exitf("HTTP server failed: %v", err)
		}
	}()
	klog.Infof("Started HTTP server listening on %s", *listen)
}

// Read output log private key from file or environment variable and generate the
// note Signer and Verifier pair for it.
func getOutputLogSignerVerifier() (note.Signer, note.Verifier, error) {
	var privKey string
	var err error
	if len(*outputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*outputLogPrivKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get private key: %w", err)
		}
	} else {
		privKey = os.Getenv("OUTPUT_LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			return nil, nil, errors.New("supply private key file path using --output_log_private_key or set OUTPUT_LOG_PRIVATE_KEY environment variable")
		}
	}
	s, v, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signer/verifier: %w", err)
	}
	return s, v, nil
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

func mapFn(data []byte) [][sha256.Size]byte {
	s := cryptobyte.String(data)

	var version, leafType uint8
	var timestamp uint64
	var certType uint16
	if !s.ReadUint8(&version) || !s.ReadUint8(&leafType) || !s.ReadUint64(&timestamp) || !s.ReadUint16(&certType) {
		klog.Warningf("Failed to unmarshal headers")
		// This should return a sentinel value (e.g. all zero hash) so unprocessable entries can be found
		return nil
	}
	var isPreCert bool
	var cert cryptobyte.String
	switch certType {
	case 0:
		// x509
		isPreCert = false
		if !s.ReadUint24LengthPrefixed(&cert) {
			klog.Warning("Failed to read x509 certificate")
			return nil
		}
	case 1:
		// precert
		isPreCert = true
		var ikh []byte
		if !s.ReadBytes(&ikh, sha256.Size) {
			klog.Warning("Failed to read issuer key hash")
			return nil
		}
		var tbsCert cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&tbsCert) {
			klog.Warning("Failed to read precert TBSCertificate")
			return nil
		}

		tbsDER := []byte(tbsCert)
		tbsCertCopy := tbsCert

		var tbsSeq cryptobyte.String
		if !tbsCertCopy.ReadASN1(&tbsSeq, 0x30) { // SEQUENCE
			klog.Warning("failed to read TBSCertificate sequence")
			return nil
		}

		if tbsSeq.PeekASN1Tag(0xA0) {
			var version cryptobyte.String
			if !tbsSeq.ReadASN1(&version, 0xA0) {
				klog.Warning("failed to read version")
				return nil
			}
		}

		var serial cryptobyte.String
		if !tbsSeq.ReadASN1(&serial, 0x02) { // INTEGER
			klog.Warning("failed to read serial number")
			return nil
		}

		var sigAlg cryptobyte.String
		if !tbsSeq.ReadASN1Element(&sigAlg, 0x30) { // SEQUENCE
			klog.Warning("failed to read signature algorithm")
			return nil
		}

		var certBuilder cryptobyte.Builder
		certBuilder.AddASN1(0x30, func(b *cryptobyte.Builder) { // SEQUENCE
			b.AddBytes(tbsDER)
			b.AddBytes([]byte(sigAlg))
			b.AddASN1(3, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0, 0})
			})
		})
		dummyCertDER, err := certBuilder.Bytes()
		if err != nil {
			klog.Warningf("failed to build dummy cert: %v", err)
			return nil
		}
		cert = cryptobyte.String(dummyCertDER)
	default:
		klog.Warningf("unknown cert type: %d", certType)
		return nil
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		klog.Warningf("failed to parse x509 cert (preCert=%t): %v", isPreCert, err)
		// This could return a sentinel value (e.g. all zero hash) so unprocessable entries can be found
		return nil
	}
	if klog.V(2).Enabled() {
		klog.V(2).Info(parsedCert.DNSNames)
	}
	uniqueNames := make(map[string]bool)
	for _, cn := range parsedCert.DNSNames {
		cn = strings.ToLower(cn)
		if strings.HasPrefix(cn, "*.") {
			cn = cn[2:]
		} else if strings.HasPrefix(cn, "*") {
			cn = cn[1:]
		}
		if cn == "" {
			continue
		}
		uniqueNames[cn] = true

		// Note on determinism vs PSL evolution:
		// The Public Suffix List (PSL) evolves over time. If the PSL used by this binary
		// is outdated and a new public suffix (e.g., a new "co.uk") is introduced,
		// we will fail to recognize it as a public suffix.
		// In that case, we will treat the new public suffix (e.g., "xx.yy") as the eTLD+1
		// and index it. This means all certificates under "*.xx.yy" will also be indexed
		// under "xx.yy", potentially causing index bloat for that key if it becomes popular.
		// This risk is accepted to maintain determinism of the indexer output for a given binary version.
		etld1, err := publicsuffix.EffectiveTLDPlusOne(cn)
		if err != nil {
			continue
		}
		if cn == etld1 {
			continue
		}
		curr := cn
		for {
			idx := strings.Index(curr, ".")
			if idx == -1 {
				break
			}
			curr = curr[idx+1:]
			if len(curr) < len(etld1) {
				break
			}
			uniqueNames[curr] = true
			if curr == etld1 {
				break
			}
		}
	}
	hashes := make([][sha256.Size]byte, 0, len(uniqueNames))
	for name := range uniqueNames {
		hashes = append(hashes, sha256.Sum256([]byte(name)))
	}
	return hashes
}
