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

package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/formats/policy"
	"golang.org/x/mod/sumdb/note"
)

// Policy verifies a signed checkpoint note against a log and witness trust policy,
// returning the parsed log.Checkpoint if valid.
type Policy interface {
	Verify(checkpoint []byte) (*f_log.Checkpoint, error)
}

func validateSignedCheckpointBytes(checkpoint []byte, expectedOrigin string) error {
	if len(checkpoint) == 0 {
		return errors.New("empty checkpoint")
	}
	if bytes.ContainsRune(checkpoint, '\r') {
		return errors.New("carriage return not allowed in checkpoint")
	}
	if !bytes.HasSuffix(checkpoint, []byte("\n")) || bytes.HasSuffix(checkpoint, []byte("\n\n")) {
		return errors.New("invalid checkpoint termination")
	}
	cpParts := bytes.Split(checkpoint, []byte("\n\n"))
	if len(cpParts) != 2 || len(cpParts[0]) == 0 || len(bytes.TrimSpace(cpParts[1])) == 0 {
		return errors.New("invalid signed checkpoint structure")
	}
	hdr, err := ParseCheckpointHeader(cpParts[0])
	if err != nil {
		return err
	}
	if expectedOrigin != "" && hdr.Origin != expectedOrigin {
		return fmt.Errorf("checkpoint origin %q does not match expected origin %q", hdr.Origin, expectedOrigin)
	}
	return nil
}

type builtPolicy struct {
	origin string
	logV   note.Verifier
	tlog   policy.TLogPolicy
}

func (p *builtPolicy) Origin() string {
	return p.origin
}

func (p *builtPolicy) Verify(checkpoint []byte) (*f_log.Checkpoint, error) {
	if err := validateSignedCheckpointBytes(checkpoint, p.origin); err != nil {
		return nil, fmt.Errorf("invalid checkpoint format: %w", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint(checkpoint, p.origin, p.logV)
	if err != nil {
		return nil, fmt.Errorf("failed to verify log checkpoint: %w", err)
	}
	if !p.tlog.Satisfied(checkpoint) {
		return nil, fmt.Errorf("checkpoint does not satisfy witness quorum %q", p.tlog.Quorum)
	}
	return cp, nil
}

type parsedPolicy struct {
	origin string
	tlog   policy.TLogPolicy
}

func (p *parsedPolicy) Origin() string {
	if p.origin != "" {
		return p.origin
	}
	if len(p.tlog.Logs) == 1 && p.tlog.Logs[0].Verifier != nil {
		return p.tlog.Logs[0].Verifier.Name()
	}
	return ""
}

func (p *parsedPolicy) Verify(checkpoint []byte) (*f_log.Checkpoint, error) {
	if err := validateSignedCheckpointBytes(checkpoint, p.Origin()); err != nil {
		return nil, fmt.Errorf("invalid checkpoint format: %w", err)
	}
	return p.tlog.Verify(checkpoint)
}

// PolicyOrigin returns the unambiguous expected checkpoint origin bound to p,
// or "" if p does not specify a single log origin.
func PolicyOrigin(p any) string {
	if op, ok := p.(interface{ Origin() string }); ok {
		return op.Origin()
	}
	return ""
}

// ParseVerifier parses a public key verifier string or file path into a note.Verifier.
//
// Supported schemes:
//  1. Standard note / C2SP log or cosignature verifier format:
//     "<name>+<hash>+<key>"
//  2. MTC format (Merkle Tree Certificates cosigned subtree signature):
//     "mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>"
func ParseVerifier(keyOrPath string) (note.Verifier, error) {
	s := strings.TrimSpace(keyOrPath)
	if s == "" {
		return nil, errors.New("empty verifier key")
	}
	isFilePath := strings.Count(s, "+") < 2
	if !isFilePath {
		if info, err := os.Stat(s); err == nil && !info.IsDir() {
			isFilePath = true
		}
	}
	if isFilePath {
		data, err := os.ReadFile(s)
		if err != nil {
			return nil, fmt.Errorf("failed to read verifier key file %q: %w", s, err)
		}
		s = string(bytes.TrimSpace(data))
		if s == "" {
			return nil, errors.New("empty verifier key")
		}
	}

	if strings.HasPrefix(s, "mtc+") {
		parts := strings.SplitN(s, "+", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("invalid MTC verifier %q: expected 'mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>'", s)
		}
		name := parts[1]
		cosignerID := parts[2]
		logID := parts[3]
		pubKeyB64 := parts[4]

		pubKeyBytes, err := strictBase64.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MTC public key base64: %w", err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid MTC Ed25519 public key size %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
		}
		return NewMTCVerifier(name, ed25519.PublicKey(pubKeyBytes), cosignerID, logID)
	}

	return f_note.NewVerifier(s)
}

// ParseWitnessVerifier parses a witness cosignature or note verifier key string or file path.
func ParseWitnessVerifier(keyOrPath string) (note.Verifier, error) {
	if strings.TrimSpace(keyOrPath) == "" {
		return nil, errors.New("empty witness verifier key")
	}
	return ParseVerifier(keyOrPath)
}

// BuildPolicy constructs a Policy enforcing log origin, primary log verifier,
// and an optional witness quorum.
func BuildPolicy(origin string, v note.Verifier, witnesses []note.Verifier, witnessThreshold int) (Policy, error) {
	if v == nil {
		return nil, errors.New("verifier is required")
	}
	effOrigin := strings.TrimSpace(origin)
	if effOrigin == "" {
		effOrigin = v.Name()
	}
	if witnessThreshold <= 0 {
		return &builtPolicy{
			origin: effOrigin,
			logV:   v,
			tlog:   policy.TLogPolicy{Quorum: "none"},
		}, nil
	}

	type verifierID struct {
		name string
		hash uint32
	}
	primaryID := verifierID{name: v.Name(), hash: v.KeyHash()}
	seen := make(map[verifierID]struct{}, len(witnesses))
	uniqueWitnesses := make([]note.Verifier, 0, len(witnesses))
	for _, w := range witnesses {
		if w == nil {
			continue
		}
		id := verifierID{name: w.Name(), hash: w.KeyHash()}
		if id == primaryID {
			return nil, errors.New("witness verifier collides with primary log verifier")
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniqueWitnesses = append(uniqueWitnesses, w)
	}
	if len(uniqueWitnesses) < witnessThreshold {
		return nil, fmt.Errorf("insufficient distinct witness verifiers: got %d, threshold %d", len(uniqueWitnesses), witnessThreshold)
	}

	polWitnesses := make([]policy.Witness, len(uniqueWitnesses))
	memberNames := make([]string, len(uniqueWitnesses))
	for i, w := range uniqueWitnesses {
		wName := fmt.Sprintf("w%d", i)
		polWitnesses[i] = policy.Witness{Name: wName, Verifier: w}
		memberNames[i] = wName
	}
	const groupName = "quorum_group"
	return &builtPolicy{
		origin: effOrigin,
		logV:   v,
		tlog: policy.TLogPolicy{
			Witnesses: polWitnesses,
			Groups: []policy.Group{
				{
					Name:      groupName,
					Threshold: uint(witnessThreshold),
					Members:   memberNames,
				},
			},
			Quorum: groupName,
		},
	}, nil
}

// ParsePolicy parses a c2sp.org/tlog-policy document into a Policy.
func ParsePolicy(b []byte) (Policy, error) {
	var p policy.TLogPolicy
	if err := p.Unmarshal(b); err != nil {
		return nil, err
	}
	return &parsedPolicy{tlog: p}, nil
}

// ParsePolicyFile reads a c2sp.org/tlog-policy file from disk and parses it into a Policy.
func ParsePolicyFile(policyPath string) (Policy, error) {
	b, err := os.ReadFile(strings.TrimSpace(policyPath))
	if err != nil {
		return nil, err
	}
	return ParsePolicy(b)
}

// ParsePolicyOrVerifier resolves either a tlog-policy file (when policyPath is non-empty)
// or builds a policy from pubKeyOrPath, origin, and optional witness quorum parameters.
func ParsePolicyOrVerifier(policyPath, pubKeyOrPath, origin string, witnesses []note.Verifier, witnessThreshold int) (Policy, error) {
	if strings.TrimSpace(policyPath) != "" {
		pol, err := ParsePolicyFile(policyPath)
		if err != nil {
			return nil, err
		}
		if pp, ok := pol.(*parsedPolicy); ok {
			pp.origin = strings.TrimSpace(origin)
		}
		return pol, nil
	}
	v, err := ParseVerifier(pubKeyOrPath)
	if err != nil {
		return nil, err
	}
	return BuildPolicy(origin, v, witnesses, witnessThreshold)
}

// MTCVerifier implements note.Verifier for MTC checkpoint signatures.
type MTCVerifier struct {
	name            string
	pubKey          ed25519.PublicKey
	keyHash         uint32
	cosignerIDBytes []byte
	logIDBytes      []byte
}

// NewMTCVerifier creates a new MTCVerifier.
func NewMTCVerifier(name string, pubKey ed25519.PublicKey, cosignerID, logID string) (*MTCVerifier, error) {
	if err := ValidateInputOrigin(name); err != nil {
		return nil, fmt.Errorf("invalid MTC verifier name: %w", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid MTC Ed25519 public key size %d, expected %d", len(pubKey), ed25519.PublicKeySize)
	}
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0a, 0xff})
	h.Write([]byte("mtc-checkpoint/v1"))
	sum := h.Sum(nil)
	keyHash := binary.BigEndian.Uint32(sum[:4])

	cosignerIDBytes, err := encodeRelativeOIDStr(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cosigner ID: %w", err)
	}
	if len(cosignerIDBytes) > 255 {
		return nil, fmt.Errorf("encoded cosigner ID length %d exceeds 255 bytes", len(cosignerIDBytes))
	}

	logIDBytes, err := encodeRelativeOIDStr(logID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode log ID: %w", err)
	}
	if len(logIDBytes) > 255 {
		return nil, fmt.Errorf("encoded log ID length %d exceeds 255 bytes", len(logIDBytes))
	}

	return &MTCVerifier{
		name:            name,
		pubKey:          bytes.Clone(pubKey),
		keyHash:         keyHash,
		cosignerIDBytes: cosignerIDBytes,
		logIDBytes:      logIDBytes,
	}, nil
}

// Name returns the verifier name.
func (v *MTCVerifier) Name() string {
	return v.name
}

// KeyHash returns the verifier key hash.
func (v *MTCVerifier) KeyHash() uint32 {
	return v.keyHash
}

// Verify verifies the signature over the checkpoint message.
func (v *MTCVerifier) Verify(msg, sig []byte) bool {
	if len(v.pubKey) != ed25519.PublicKeySize || bytes.ContainsRune(msg, '\r') {
		return false
	}
	lines := strings.Split(string(msg), "\n")
	if len(lines) != 3 && (len(lines) != 4 || lines[3] != "") {
		return false
	}
	if err := ValidateInputOrigin(lines[0]); err != nil {
		return false
	}
	size, err := parseUint64Strict(lines[1])
	if err != nil {
		return false
	}
	if len(lines[2]) != 44 {
		return false
	}
	hash, err := strictBase64.DecodeString(lines[2])
	if err != nil || len(hash) != sha256.Size {
		return false
	}

	if len(v.cosignerIDBytes) > 255 || len(v.logIDBytes) > 255 {
		return false
	}

	var input []byte
	input = append(input, []byte("mtc-subtree/v1\n")...)
	input = append(input, 0)
	input = append(input, byte(len(v.cosignerIDBytes)))
	input = append(input, v.cosignerIDBytes...)
	input = append(input, byte(len(v.logIDBytes)))
	input = append(input, v.logIDBytes...)

	var startBytes [8]byte
	binary.BigEndian.PutUint64(startBytes[:], 0)
	input = append(input, startBytes[:]...)

	var endBytes [8]byte
	binary.BigEndian.PutUint64(endBytes[:], size)
	input = append(input, endBytes[:]...)

	input = append(input, hash...)

	return ed25519.Verify(v.pubKey, input, sig)
}

var _ note.Verifier = (*MTCVerifier)(nil)

func encodeRelativeOIDStr(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty relative OID")
	}
	parts := strings.Split(s, ".")
	components := make([]uint32, 0, len(parts))
	for _, p := range parts {
		v, err := parseUint64Strict(p)
		if err != nil {
			return nil, err
		}
		if v > math.MaxUint32 {
			return nil, fmt.Errorf("OID arc %q overflows uint32", p)
		}
		components = append(components, uint32(v))
	}
	return encodeRelativeOID(components), nil
}

func encodeRelativeOID(components []uint32) []byte {
	var encoded []byte
	for _, c := range components {
		encoded = append(encoded, encodeBase128(c)...)
	}
	return encoded
}

func encodeBase128(v uint32) []byte {
	if v == 0 {
		return []byte{0}
	}
	var chunks []byte
	for v > 0 {
		chunks = append(chunks, byte(v&0x7f))
		v >>= 7
	}
	encoded := make([]byte, 0, len(chunks))
	for i := len(chunks) - 1; i >= 0; i-- {
		b := chunks[i]
		if i > 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
	}
	return encoded
}
