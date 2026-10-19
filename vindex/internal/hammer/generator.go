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

// Package hammer provides synthetic load generation, pure-Go mapping oracle verification,
// and C2SP tlog-vindex conformance checks.
package hammer

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
)

// Distribution defines the key selection distribution.
type Distribution string

const (
	DistZipf    Distribution = "zipf"
	DistUniform Distribution = "uniform"

	maxCTDomainsPerLeaf = 500
)

// LeafFormat defines the raw payload formatting for synthetic leaves.
type LeafFormat string

const (
	FormatRaw   LeafFormat = "raw"   // Leaf is a raw canonical key (including RFC 3986 reserved delimiters)
	FormatSumDB LeafFormat = "sumdb" // Leaf is a two-line Go SumDB record ("<mod> <ver> h1:...\n<mod> <ver>/go.mod h1:...\n")
	FormatCT    LeafFormat = "ct"    // Leaf is an RFC 6962 X.509 MerkleTreeLeaf with SAN dNSNames and wildcards
)

// GeneratorConfig configures the synthetic leaf generator.
type GeneratorConfig struct {
	Distribution Distribution
	NumKeys      uint64
	ZipfS        float64 // Skew parameter for Zipf (s > 1.0, e.g. 1.2)
	ZipfV        float64 // Scale parameter for Zipf (v >= 1.0, e.g. 1.0)
	Seed         int64
	LeafFormat   LeafFormat
	CTMinDomains int
	CTMaxDomains int
}

// LeafEntry represents a generated leaf with its primary canonical key.
type LeafEntry struct {
	LeafData []byte
	Key      string
}

// Generator generates synthetic leaves with configurable key distributions.
type Generator struct {
	mu          sync.Mutex
	cfg         GeneratorConfig
	rng         *rand.Rand
	zipf        *rand.Zipf
	ctPriv      ed25519.PrivateKey
	ctPub       ed25519.PublicKey
	totalLeaves uint64
}

// NewGenerator creates a new Generator instance.
func NewGenerator(cfg GeneratorConfig) *Generator {
	if cfg.NumKeys == 0 {
		cfg.NumKeys = 10000
	}
	if math.IsNaN(cfg.ZipfS) || math.IsInf(cfg.ZipfS, 0) || cfg.ZipfS <= 1.0 {
		cfg.ZipfS = 1.2
	}
	if math.IsNaN(cfg.ZipfV) || math.IsInf(cfg.ZipfV, 0) || cfg.ZipfV < 1.0 {
		cfg.ZipfV = 1.0
	}
	if cfg.Seed == 0 {
		cfg.Seed = 42
	}
	if cfg.LeafFormat == "" {
		cfg.LeafFormat = FormatRaw
	}
	if cfg.CTMinDomains <= 0 {
		cfg.CTMinDomains = 1
	}
	if cfg.CTMinDomains > maxCTDomainsPerLeaf {
		cfg.CTMinDomains = maxCTDomainsPerLeaf
	}
	if cfg.CTMaxDomains <= 0 {
		cfg.CTMaxDomains = 50
	}
	if cfg.CTMaxDomains > maxCTDomainsPerLeaf {
		cfg.CTMaxDomains = maxCTDomainsPerLeaf
	}
	if cfg.CTMaxDomains < cfg.CTMinDomains {
		cfg.CTMaxDomains = cfg.CTMinDomains
	}

	rng := rand.New(rand.NewSource(cfg.Seed))
	var zipf *rand.Zipf
	if cfg.Distribution != DistUniform && cfg.NumKeys > 1 {
		zipf = rand.NewZipf(rng, cfg.ZipfS, cfg.ZipfV, cfg.NumKeys-1)
	}

	ctPub, ctPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic(fmt.Sprintf("hammer: failed to generate synthetic X.509 key: %v", err))
	}

	return &Generator{
		cfg:    cfg,
		rng:    rng,
		zipf:   zipf,
		ctPriv: ctPriv,
		ctPub:  ctPub,
	}
}

// LeafFormat returns the configured synthetic LeafFormat.
func (g *Generator) LeafFormat() LeafFormat {
	return g.cfg.LeafFormat
}

func sumDBRawModuleForID(id uint64) string {
	if id%4 == 3 {
		return fmt.Sprintf("example.com/Mod-%d/pkg", id)
	}
	return fmt.Sprintf("example.com/module-%d/pkg", id)
}

func (g *Generator) keyForIDLocked(id uint64) string {
	switch g.cfg.LeafFormat {
	case FormatCT:
		return fmt.Sprintf("com.domain-%d.", id)
	case FormatSumDB:
		escaped, err := module.EscapePath(sumDBRawModuleForID(id))
		if err != nil {
			panic(fmt.Sprintf("hammer: invalid synthetic SumDB module path for id %d: %v", id, err))
		}
		return escaped
	default:
		return KeyForID(id)
	}
}

func buildRFC6962X509Leaf(serial uint64, dnsNames []string, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(serial),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Unix(1_700_000_000, 0).UTC(),
		NotAfter:     time.Unix(1_800_000_000, 0).UTC(),
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		panic(fmt.Sprintf("hammer: failed to build synthetic X.509 certificate: %v", err))
	}
	// RFC 6962 MerkleTreeLeaf: version(0) || leaf_type(0) || timestamp(8) || entry_type(0=x509) || cert_len(3) || certDER || ext_len(2=0)
	leaf := make([]byte, 17+len(certDER))
	binary.BigEndian.PutUint64(leaf[2:10], 1_700_000_000_000+serial)
	leaf[12] = byte(len(certDER) >> 16)
	leaf[13] = byte(len(certDER) >> 8)
	leaf[14] = byte(len(certDER))
	copy(leaf[15:], certDER)
	return leaf
}

// NextLeaf generates the next sequential leaf entry according to the configured distribution.
func (g *Generator) NextLeaf() LeafEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.totalLeaves++
	ver := g.totalLeaves

	if g.cfg.LeafFormat == FormatCT {
		count := g.cfg.CTMinDomains
		if g.cfg.CTMaxDomains > g.cfg.CTMinDomains {
			count = g.cfg.CTMinDomains + g.rng.Intn(g.cfg.CTMaxDomains-g.cfg.CTMinDomains+1)
		}

		domainIDs := make([]uint64, 0, count)
		seen := make(map[uint64]struct{}, count)
		for range count {
			id := g.sampleKeyIDLocked()
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				domainIDs = append(domainIDs, id)
			}
		}

		dnsNames := make([]string, 0, len(domainIDs)*3)
		for i, id := range domainIDs {
			dnsNames = append(dnsNames,
				fmt.Sprintf("domain-%d.com", id),
				fmt.Sprintf("sub-%d.domain-%d.com", i+1, id),
			)
			if id%4 == 3 {
				dnsNames = append(dnsNames, fmt.Sprintf("*.domain-%d.com", id))
			}
		}

		return LeafEntry{
			LeafData: buildRFC6962X509Leaf(ver, dnsNames, g.ctPub, g.ctPriv),
			Key:      g.keyForIDLocked(domainIDs[0]),
		}
	}

	id := g.sampleKeyIDLocked()
	keyStr := g.keyForIDLocked(id)
	var leafData []byte
	if g.cfg.LeafFormat == FormatSumDB {
		rawMod := sumDBRawModuleForID(id)
		h1 := sha256.Sum256(fmt.Appendf(nil, "%s@v1.%d.0", rawMod, ver))
		h2 := sha256.Sum256(fmt.Appendf(nil, "%s@v1.%d.0/go.mod", rawMod, ver))
		leafData = fmt.Appendf(nil, "%s v1.%d.0 h1:%s\n%s v1.%d.0/go.mod h1:%s\n",
			rawMod, ver, base64.StdEncoding.EncodeToString(h1[:]),
			rawMod, ver, base64.StdEncoding.EncodeToString(h2[:]))
	} else {
		leafData = []byte(keyStr)
	}

	return LeafEntry{
		LeafData: leafData,
		Key:      keyStr,
	}
}

// SampleUniformKey samples a key uniformly across [0, NumKeys).
func (g *Generator) SampleUniformKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.keyForIDLocked(g.sampleUniformIDLocked())
}

// SampleHotKey samples from the top 1% hottest keys in the working set.
func (g *Generator) SampleHotKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	hotCount := max(g.cfg.NumKeys/100, 1)
	if hotCount > math.MaxInt64 {
		hotCount = math.MaxInt64
	}
	keyID := uint64(g.rng.Int63n(int64(hotCount)))
	return g.keyForIDLocked(keyID)
}

// SamplePrefix returns a canonical key prefix expected to match one or more keys in the working set.
func (g *Generator) SamplePrefix() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	hotCount := max(g.cfg.NumKeys/100, 1)
	if hotCount > math.MaxInt64 {
		hotCount = math.MaxInt64
	}
	id := uint64(g.rng.Int63n(int64(hotCount)))
	switch g.cfg.LeafFormat {
	case FormatCT:
		return fmt.Sprintf("com.domain-%d.", id)
	case FormatSumDB:
		return strings.TrimSuffix(g.keyForIDLocked(id), "pkg")
	default:
		// Strip any trailing RFC 3986 delimiter suffix on id%8==7 so prefixes match broad module families too.
		return fmt.Sprintf("example.com/module-%d", id)
	}
}

// SampleNonInclusionKey returns a canonical key guaranteed not to exist in the log.
func (g *Generator) SampleNonInclusionKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := g.cfg.NumKeys + uint64(g.rng.Int63n(1000000)) + 1
	if g.cfg.LeafFormat == FormatCT {
		return fmt.Sprintf("com.nonexistent-domain-%d.", id)
	}
	return fmt.Sprintf("nonexistent.example.com/pkg-%d", id)
}

// SampleNonInclusionPrefix returns a canonical key prefix guaranteed not to match any key in the log,
// formatted on a domain/namespace boundary ('com.nonexistent-domain-<id>.' or 'nonexistent.example.com/pkg-<id>/')
// so servers enforcing domain or '/'-delimited namespace prefix policies accept it.
func (g *Generator) SampleNonInclusionPrefix() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := g.cfg.NumKeys + uint64(g.rng.Int63n(1000000)) + 1
	if g.cfg.LeafFormat == FormatCT {
		return fmt.Sprintf("com.nonexistent-domain-%d.", id)
	}
	return fmt.Sprintf("nonexistent.example.com/pkg-%d/", id)
}

func (g *Generator) sampleUniformIDLocked() uint64 {
	numKeys := g.cfg.NumKeys
	if numKeys > math.MaxInt64 {
		numKeys = math.MaxInt64
	}
	return uint64(g.rng.Int63n(int64(numKeys)))
}

func (g *Generator) sampleKeyIDLocked() uint64 {
	if g.cfg.Distribution == DistUniform || g.zipf == nil {
		return g.sampleUniformIDLocked()
	}
	return g.zipf.Uint64()
}

// KeyForID returns the deterministic canonical key string for a given key ID in FormatRaw.
// Every 8th key ID embeds RFC 3986 query delimiters ('+', '=', '&') and unreserved '~'
// to exercise strict percent-encoding and server query unescaping.
func KeyForID(id uint64) string {
	if id%8 == 7 {
		return fmt.Sprintf("example.com/module-%d+meta=1&tag~v2", id)
	}
	return fmt.Sprintf("example.com/module-%d", id)
}

func rateToInterval(rate float64, minInterval time.Duration) time.Duration {
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 {
		return minInterval
	}
	ns := float64(time.Second) / rate
	if ns >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return max(time.Duration(ns), minInterval)
}
