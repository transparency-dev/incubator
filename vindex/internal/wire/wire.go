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

// Package wire implements C2SP tlog-vindex wire formatting, section parsing,
// Output Log leaf encoding, and RFC 6962 value log compact range root computation.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	f_proof "github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = errors.New("output log leaf format corrupted")

var strictBase64 = base64.StdEncoding.Strict()

// OutputLogLeaf represents a parsed 6-line c2sp.org/tlog-vindex-state@v1 Output Log entry.
type OutputLogLeaf struct {
	InputOrigin string
	From        uint64
	InputSize   uint64
	InputRoot   [sha256.Size]byte
	MPTRoot     [sha256.Size]byte
	InCP        *log.Checkpoint
}

// KeyValueRoot represents a canonical key and its 32-byte value log root yielded by a prefix scan or point lookup.
type KeyValueRoot struct {
	Key       string
	ValueRoot [sha256.Size]byte
}

// PrefixKeyVal is an alias for KeyValueRoot.
type PrefixKeyVal = KeyValueRoot

// KeysSection represents a parsed c2sp.org/tlog-vindex-keys@v1 stanza.
type KeysSection struct {
	MPTProof []byte
	Matches  []KeyValueRoot
}

// ValidateCanonicalKey checks that key is between 1 and 1024 printable ASCII bytes (0x21..0x7E),
// containing no NUL (0x00) bytes or ASCII whitespace.
func ValidateCanonicalKey(key []byte) error {
	if len(key) == 0 || len(key) > 1024 {
		return fmt.Errorf("invalid canonical key length %d: must be 1..1024 bytes", len(key))
	}
	for _, b := range key {
		if b < 0x21 || b > 0x7E {
			return fmt.Errorf("invalid canonical key byte 0x%02x: must be printable ASCII 0x21..0x7E", b)
		}
	}
	return nil
}

// ValidateInputOrigin checks that origin is a non-empty printable ASCII string in 0x20..0x7E
// with no leading or trailing spaces.
func ValidateInputOrigin(origin string) error {
	if origin == "" {
		return errors.New("empty input-origin")
	}
	if origin[0] == ' ' || origin[len(origin)-1] == ' ' {
		return fmt.Errorf("input-origin %q must not have leading or trailing spaces", origin)
	}
	for i := 0; i < len(origin); i++ {
		if origin[i] < 0x20 || origin[i] > 0x7E {
			return fmt.Errorf("invalid byte 0x%02x in input-origin %q: must be printable ASCII 0x20..0x7E", origin[i], origin)
		}
	}
	return nil
}

// PercentEncodeCanonicalKey percent-encodes any byte outside the RFC 3986 unreserved set
// (ALPHA, DIGIT, '-', '.', '_', '~'), escaping '+' as "%2B" and query delimiters.
func PercentEncodeCanonicalKey(key string) string {
	const hexUpper = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(key))
	for i := 0; i < len(key); i++ {
		b := key[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '.' || b == '_' || b == '~' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexUpper[b>>4])
			sb.WriteByte(hexUpper[b&0x0F])
		}
	}
	return sb.String()
}

// BindingSection represents a parsed c2sp.org/tlog-proof@v1 stanza and trailing Output Log checkpoint.
type BindingSection struct {
	InputOrigin    string
	From           uint64
	InputSize      uint64
	InputRoot      [sha256.Size]byte
	MPTRoot        [sha256.Size]byte
	OutLeafIdx     uint64
	InclusionProof [][]byte
	OutSignedCP    []byte
	RawOutLeaf     []byte
	RawProofAndCP  []byte
}

// ValuesSection represents a parsed c2sp.org/tlog-vindex-values@v1 response.
type ValuesSection struct {
	Preceding    uint64
	CompactRange [][sha256.Size]byte
	Indices      []uint64
}

func parseUint64Strict(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zeroes not allowed in %q", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid decimal character in %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

// ParseCheckpointHeader parses a raw signed-note / tlog-checkpoint header extracting Origin, Size, and Hash.
func ParseCheckpointHeader(rawCP []byte) (*log.Checkpoint, error) {
	if bytes.ContainsRune(rawCP, '\r') {
		return nil, errors.New("carriage return not allowed in checkpoint")
	}
	lines := bytes.Split(rawCP, []byte("\n"))
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid checkpoint format: expected at least 3 lines, got %d", len(lines))
	}
	origin := string(lines[0])
	if err := ValidateInputOrigin(origin); err != nil {
		return nil, fmt.Errorf("invalid checkpoint origin %q: %w", origin, err)
	}
	size, err := parseUint64Strict(string(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint size %q: %w", string(lines[1]), err)
	}
	hashStr := string(lines[2])
	if len(hashStr) != 44 {
		return nil, fmt.Errorf("failed to decode 32-byte checkpoint root hash %q: invalid base64 length %d", hashStr, len(hashStr))
	}
	hashBytes, err := strictBase64.DecodeString(hashStr)
	if err != nil || len(hashBytes) != 32 {
		return nil, fmt.Errorf("failed to decode 32-byte checkpoint root hash %q", hashStr)
	}
	return &log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hashBytes,
	}, nil
}

// ParseOutputLogLeafFull parses a raw 6-line Output Log entry payload (c2sp.org/tlog-vindex-state@v1).
func ParseOutputLogLeafFull(leafData []byte) (*OutputLogLeaf, error) {
	if len(leafData) == 0 {
		return nil, fmt.Errorf("%w: empty leaf data", ErrOutputLogCorrupted)
	}
	if bytes.ContainsRune(leafData, '\r') {
		return nil, fmt.Errorf("%w: carriage return not allowed in leaf", ErrOutputLogCorrupted)
	}
	if leafData[len(leafData)-1] != '\n' {
		return nil, fmt.Errorf("%w: leaf must end with a newline", ErrOutputLogCorrupted)
	}
	lines := bytes.Split(leafData[:len(leafData)-1], []byte("\n"))
	if len(lines) != 6 {
		return nil, fmt.Errorf("%w: expected exactly 6 lines in tlog-vindex-state@v1, got %d", ErrOutputLogCorrupted, len(lines))
	}
	if string(lines[0]) != "c2sp.org/tlog-vindex-state@v1" {
		return nil, fmt.Errorf("%w: invalid leaf header %q", ErrOutputLogCorrupted, string(lines[0]))
	}
	if !bytes.HasPrefix(lines[1], []byte("input-origin ")) {
		return nil, fmt.Errorf("%w: expected 'input-origin ' line, got %q", ErrOutputLogCorrupted, string(lines[1]))
	}
	inputOrigin := string(lines[1][len("input-origin "):])
	if err := ValidateInputOrigin(inputOrigin); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOutputLogCorrupted, err)
	}

	if !bytes.HasPrefix(lines[2], []byte("from ")) {
		return nil, fmt.Errorf("%w: expected 'from ' line, got %q", ErrOutputLogCorrupted, string(lines[2]))
	}
	from, err := parseUint64Strict(string(lines[2][len("from "):]))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid from index: %w", ErrOutputLogCorrupted, err)
	}

	if !bytes.HasPrefix(lines[3], []byte("input-size ")) {
		return nil, fmt.Errorf("%w: expected 'input-size ' line, got %q", ErrOutputLogCorrupted, string(lines[3]))
	}
	inputSize, err := parseUint64Strict(string(lines[3][len("input-size "):]))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid input-size: %w", ErrOutputLogCorrupted, err)
	}
	if from > inputSize {
		return nil, fmt.Errorf("%w: from (%d) exceeds input-size (%d)", ErrOutputLogCorrupted, from, inputSize)
	}

	if !bytes.HasPrefix(lines[4], []byte("input-root ")) {
		return nil, fmt.Errorf("%w: expected 'input-root ' line, got %q", ErrOutputLogCorrupted, string(lines[4]))
	}
	inRootB64 := string(lines[4][len("input-root "):])
	if len(inRootB64) != 44 {
		return nil, fmt.Errorf("%w: invalid input-root base64 length %d", ErrOutputLogCorrupted, len(inRootB64))
	}
	inRootBytes, err := strictBase64.DecodeString(inRootB64)
	if err != nil || len(inRootBytes) != sha256.Size {
		return nil, fmt.Errorf("%w: invalid input-root base64 %q: %v", ErrOutputLogCorrupted, inRootB64, err)
	}
	var inputRoot [sha256.Size]byte
	copy(inputRoot[:], inRootBytes)

	if !bytes.HasPrefix(lines[5], []byte("mpt-root ")) {
		return nil, fmt.Errorf("%w: expected 'mpt-root ' line, got %q", ErrOutputLogCorrupted, string(lines[5]))
	}
	mptRootB64 := string(lines[5][len("mpt-root "):])
	if len(mptRootB64) != 44 {
		return nil, fmt.Errorf("%w: invalid mpt-root base64 length %d", ErrOutputLogCorrupted, len(mptRootB64))
	}
	mptRootBytes, err := strictBase64.DecodeString(mptRootB64)
	if err != nil || len(mptRootBytes) != sha256.Size {
		return nil, fmt.Errorf("%w: invalid mpt-root base64 %q: %v", ErrOutputLogCorrupted, mptRootB64, err)
	}
	var mptRoot [sha256.Size]byte
	copy(mptRoot[:], mptRootBytes)

	return &OutputLogLeaf{
		InputOrigin: inputOrigin,
		From:        from,
		InputSize:   inputSize,
		InputRoot:   inputRoot,
		MPTRoot:     mptRoot,
		InCP: &log.Checkpoint{
			Origin: inputOrigin,
			Size:   inputSize,
			Hash:   bytes.Clone(inputRoot[:]),
		},
	}, nil
}

// ParseOutputLogLeaf parses a raw Output Log leaf payload into the 32-byte MPTRoot
// and the unsigned Input Log checkpoint header (Origin, Size, Hash).
func ParseOutputLogLeaf(leafData []byte) (mptRoot [sha256.Size]byte, inCP *log.Checkpoint, err error) {
	leaf, err := ParseOutputLogLeafFull(leafData)
	if err != nil {
		return [sha256.Size]byte{}, nil, err
	}
	return leaf.MPTRoot, leaf.InCP, nil
}

// FormatStateEntry formats a 6-line Output Log state commitment entry according to c2sp.org/tlog-vindex-state@v1.
func FormatStateEntry(inputOrigin string, from, inputSize uint64, inputRoot, mptRoot [sha256.Size]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("c2sp.org/tlog-vindex-state@v1\n")
	buf.WriteString("input-origin ")
	buf.WriteString(inputOrigin)
	buf.WriteByte('\n')
	buf.WriteString("from ")
	buf.WriteString(strconv.FormatUint(from, 10))
	buf.WriteByte('\n')
	buf.WriteString("input-size ")
	buf.WriteString(strconv.FormatUint(inputSize, 10))
	buf.WriteByte('\n')
	buf.WriteString("input-root ")
	buf.WriteString(base64.StdEncoding.EncodeToString(inputRoot[:]))
	buf.WriteByte('\n')
	buf.WriteString("mpt-root ")
	buf.WriteString(base64.StdEncoding.EncodeToString(mptRoot[:]))
	buf.WriteByte('\n')
	return buf.Bytes()
}

// FormatOutputLogLeafFull formats a 6-line Output Log leaf from an Input Log checkpoint header, start index from, and MPTRoot.
func FormatOutputLogLeafFull(mptRoot [sha256.Size]byte, from uint64, inCP *log.Checkpoint) []byte {
	var origin string
	var size uint64
	var inRoot [sha256.Size]byte
	if inCP != nil {
		origin = inCP.Origin
		size = inCP.Size
		copy(inRoot[:], inCP.Hash)
	}
	return FormatStateEntry(origin, from, size, inRoot, mptRoot)
}

// FormatOutputLogLeaf formats a 6-line Output Log leaf with from=0.
func FormatOutputLogLeaf(mptRoot [sha256.Size]byte, inCP *log.Checkpoint) []byte {
	return FormatOutputLogLeafFull(mptRoot, 0, inCP)
}

// FormatKeysSection formats the c2sp.org/tlog-vindex-keys@v1 stanza.
func FormatKeysSection(mptProof []byte, mode string, matches []KeyValueRoot) []byte {
	_ = mode
	var buf bytes.Buffer
	buf.WriteString("c2sp.org/tlog-vindex-keys@v1\n")
	if len(mptProof) > 0 {
		buf.WriteString("proof ")
		buf.WriteString(base64.StdEncoding.EncodeToString(mptProof))
		buf.WriteByte('\n')
	} else {
		buf.WriteString("proof\n")
	}
	for _, m := range matches {
		buf.WriteString(m.Key)
		buf.WriteByte(' ')
		buf.WriteString(base64.StdEncoding.EncodeToString(m.ValueRoot[:]))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// ParseKeysSection parses a c2sp.org/tlog-vindex-keys@v1 stanza.
func ParseKeysSection(section []byte) (*KeysSection, error) {
	if len(section) == 0 {
		return nil, errors.New("empty keys section")
	}
	if bytes.ContainsRune(section, '\r') {
		return nil, errors.New("carriage return not allowed in keys section")
	}
	trimmed := bytes.TrimSuffix(section, []byte("\n"))
	if len(trimmed) == 0 || bytes.HasSuffix(trimmed, []byte("\n")) {
		return nil, errors.New("invalid trailing newlines in keys section")
	}
	lines := strings.Split(string(trimmed), "\n")
	if len(lines) < 2 || lines[0] != "c2sp.org/tlog-vindex-keys@v1" {
		return nil, fmt.Errorf("invalid keys section header")
	}
	var mptProof []byte
	if lines[1] == "proof" {
		mptProof = nil
	} else if strings.HasPrefix(lines[1], "proof ") {
		b64 := lines[1][len("proof "):]
		if b64 == "" {
			return nil, errors.New("empty proof base64 after trailing space not allowed; use bare 'proof'")
		}
		decoded, err := strictBase64.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in proof line: %w", err)
		}
		if len(decoded) == 0 {
			return nil, errors.New("empty proof base64 not allowed; use bare 'proof'")
		}
		mptProof = decoded
	} else {
		return nil, fmt.Errorf("missing proof line in keys section: got %q", lines[1])
	}

	var matches []KeyValueRoot
	for idx := 2; idx < len(lines); idx++ {
		line := lines[idx]
		spaceIdx := strings.IndexByte(line, ' ')
		if spaceIdx <= 0 || strings.LastIndexByte(line, ' ') != spaceIdx {
			return nil, fmt.Errorf("invalid key-value-root line %q", line)
		}
		key := line[:spaceIdx]
		if err := ValidateCanonicalKey([]byte(key)); err != nil {
			return nil, fmt.Errorf("invalid key in line %q: %w", line, err)
		}
		valB64 := line[spaceIdx+1:]
		if len(valB64) != 44 {
			return nil, fmt.Errorf("invalid value root base64 length in line %q", line)
		}
		valBytes, err := strictBase64.DecodeString(valB64)
		if err != nil || len(valBytes) != sha256.Size {
			return nil, fmt.Errorf("invalid value root base64 in line %q", line)
		}
		var valueRoot [sha256.Size]byte
		copy(valueRoot[:], valBytes)
		matches = append(matches, KeyValueRoot{Key: key, ValueRoot: valueRoot})
	}

	for i := 1; i < len(matches); i++ {
		if matches[i].Key <= matches[i-1].Key {
			return nil, fmt.Errorf("keys not in strictly ascending order: %q vs %q", matches[i-1].Key, matches[i].Key)
		}
	}

	return &KeysSection{
		MPTProof: mptProof,
		Matches:  matches,
	}, nil
}

// FormatBindingSection formats the c2sp.org/tlog-proof@v1 stanza and trailing Output Log checkpoint.
func FormatBindingSection(outLeafRaw []byte, leafIdx uint64, inclusionProof [][]byte, outSignedCP []byte) []byte {
	hashes := make([][sha256.Size]byte, len(inclusionProof))
	for i, p := range inclusionProof {
		copy(hashes[i][:], p)
	}
	trimmed := bytes.TrimRight(outSignedCP, "\n")
	cp := make([]byte, len(trimmed)+1)
	copy(cp, trimmed)
	cp[len(trimmed)] = '\n'
	return (f_proof.TLogProof{
		ExtraData:  outLeafRaw,
		Index:      leafIdx,
		Hashes:     hashes,
		Checkpoint: cp,
	}).Marshal()
}

// ParseBindingSection parses the c2sp.org/tlog-proof@v1 stanza and trailing Output Log checkpoint.
func ParseBindingSection(section []byte) (*BindingSection, error) {
	if len(section) == 0 {
		return nil, errors.New("empty binding section")
	}
	if bytes.ContainsRune(section, '\r') {
		return nil, errors.New("carriage return not allowed in binding section")
	}
	if !bytes.HasSuffix(section, []byte("\n")) || bytes.HasSuffix(section, []byte("\n\n")) {
		return nil, errors.New("invalid binding section termination")
	}
	parts := bytes.SplitN(section, []byte("\n\n"), 2)
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return nil, errors.New("binding section must contain tlog-proof stanza and output log checkpoint")
	}
	proofLines := strings.Split(string(parts[0]), "\n")
	if len(proofLines) < 3 {
		return nil, errors.New("tlog-proof stanza requires at least 3 lines")
	}
	if len(proofLines)-3 > 63 {
		return nil, fmt.Errorf("too many audit path hashes in tlog-proof: got %d, max 63", len(proofLines)-3)
	}
	if proofLines[0] != "c2sp.org/tlog-proof@v1" {
		return nil, fmt.Errorf("invalid tlog-proof header %q", proofLines[0])
	}
	if !strings.HasPrefix(proofLines[1], "extra ") {
		return nil, fmt.Errorf("expected 'extra ' line in tlog-proof, got %q", proofLines[1])
	}
	extraB64 := proofLines[1][len("extra "):]
	if extraB64 == "" {
		return nil, errors.New("empty extra field in tlog-proof")
	}
	if _, err := strictBase64.DecodeString(extraB64); err != nil {
		return nil, fmt.Errorf("invalid base64 in extra field: %w", err)
	}
	if !strings.HasPrefix(proofLines[2], "index ") {
		return nil, fmt.Errorf("expected 'index ' line in tlog-proof, got %q", proofLines[2])
	}
	if _, err := parseUint64Strict(proofLines[2][len("index "):]); err != nil {
		return nil, fmt.Errorf("invalid index in tlog-proof: %w", err)
	}
	for i := 3; i < len(proofLines); i++ {
		hB64 := proofLines[i]
		if len(hB64) != 44 {
			return nil, fmt.Errorf("invalid audit path hash length in line %d", i)
		}
		if _, err := strictBase64.DecodeString(hB64); err != nil {
			return nil, fmt.Errorf("invalid audit path hash in line %d", i)
		}
	}

	var tp f_proof.TLogProof
	if err := tp.Unmarshal(section); err != nil {
		return nil, err
	}
	if len(tp.ExtraData) == 0 {
		return nil, errors.New("empty extra field in tlog-proof")
	}
	outLeaf, err := ParseOutputLogLeafFull(tp.ExtraData)
	if err != nil {
		return nil, fmt.Errorf("invalid output log leaf in extra field: %w", err)
	}

	inclusionProof := make([][]byte, len(tp.Hashes))
	for i := range tp.Hashes {
		hCopy := make([]byte, sha256.Size)
		copy(hCopy, tp.Hashes[i][:])
		inclusionProof[i] = hCopy
	}

	outSignedCP := tp.Checkpoint
	if !bytes.HasSuffix(outSignedCP, []byte("\n")) || bytes.HasSuffix(outSignedCP, []byte("\n\n")) {
		return nil, errors.New("invalid output log checkpoint termination")
	}
	cpParts := bytes.Split(outSignedCP, []byte("\n\n"))
	if len(cpParts) != 2 || len(cpParts[0]) == 0 || len(bytes.TrimSpace(cpParts[1])) == 0 {
		return nil, errors.New("invalid output log checkpoint structure")
	}
	if _, err := ParseCheckpointHeader(cpParts[0]); err != nil {
		return nil, fmt.Errorf("invalid output log checkpoint header: %w", err)
	}

	return &BindingSection{
		InputOrigin:    outLeaf.InputOrigin,
		From:           outLeaf.From,
		InputSize:      outLeaf.InputSize,
		InputRoot:      outLeaf.InputRoot,
		MPTRoot:        outLeaf.MPTRoot,
		OutLeafIdx:     tp.Index,
		InclusionProof: inclusionProof,
		OutSignedCP:    outSignedCP,
		RawOutLeaf:     tp.ExtraData,
		RawProofAndCP:  bytes.Clone(section),
	}, nil
}

// FormatKeysResponseFull builds the plain-text C2SP response for GET <index-url>/keys?key=<key> or ?prefix=<prefix>.
func FormatKeysResponseFull(rawCheckpoint []byte, outputLogIndex uint64, mptRoot [sha256.Size]byte, from uint64, inCP *log.Checkpoint, outputLogProof [][sha256.Size]byte, mode string, mptProof []byte, matches []KeyValueRoot) []byte {
	keysSec := FormatKeysSection(mptProof, mode, matches)
	outLeafRaw := FormatOutputLogLeafFull(mptRoot, from, inCP)
	proofBytes := make([][]byte, len(outputLogProof))
	for i := range outputLogProof {
		proofBytes[i] = outputLogProof[i][:]
	}
	bindSec := FormatBindingSection(outLeafRaw, outputLogIndex, proofBytes, rawCheckpoint)

	var sb bytes.Buffer
	sb.Write(keysSec)
	sb.WriteByte('\n')
	sb.Write(bindSec)
	return sb.Bytes()
}

// FormatKeysResponse builds the plain-text C2SP response for GET <index-url>/keys?key=<key> or ?prefix=<prefix>
// with default from=0.
func FormatKeysResponse(rawCheckpoint []byte, outputLogIndex uint64, mptRoot [sha256.Size]byte, inCP *log.Checkpoint, outputLogProof [][sha256.Size]byte, mode string, mptProof []byte, matches []KeyValueRoot) []byte {
	return FormatKeysResponseFull(rawCheckpoint, outputLogIndex, mptRoot, 0, inCP, outputLogProof, mode, mptProof, matches)
}

// FormatValuesResponse builds the plain-text C2SP response for GET <index-url>/values?key=<key>&before=<N>.
func FormatValuesResponse(preceding uint64, compactRange [][sha256.Size]byte, indices []uint64) []byte {
	var sb bytes.Buffer
	sb.WriteString("c2sp.org/tlog-vindex-values@v1\n")
	sb.WriteString("preceding ")
	sb.WriteString(strconv.FormatUint(preceding, 10))
	sb.WriteByte('\n')
	for _, h := range compactRange {
		sb.WriteString(base64.StdEncoding.EncodeToString(h[:]))
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n')
	for _, idx := range indices {
		sb.WriteString(strconv.FormatUint(idx, 10))
		sb.WriteByte('\n')
	}
	return sb.Bytes()
}

// ParseValuesResponse parses a c2sp.org/tlog-vindex-values@v1 response body.
func ParseValuesResponse(body []byte) (*ValuesSection, error) {
	if len(body) == 0 {
		return nil, errors.New("empty values response")
	}
	if bytes.ContainsRune(body, '\r') {
		return nil, errors.New("carriage return not allowed in values response")
	}
	if !bytes.HasSuffix(body, []byte("\n")) || bytes.HasSuffix(body, []byte("\n\n")) {
		return nil, errors.New("invalid values response termination")
	}
	parts := bytes.Split(body, []byte("\n\n"))
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return nil, errors.New("values response must contain header block and indices block separated by a single blank line")
	}
	headerLines := strings.Split(string(parts[0]), "\n")
	if len(headerLines) < 2 {
		return nil, errors.New("values header block requires at least 2 lines")
	}
	if headerLines[0] != "c2sp.org/tlog-vindex-values@v1" {
		return nil, fmt.Errorf("invalid values header %q", headerLines[0])
	}
	if !strings.HasPrefix(headerLines[1], "preceding ") {
		return nil, fmt.Errorf("expected 'preceding ' line, got %q", headerLines[1])
	}
	preceding, err := parseUint64Strict(headerLines[1][len("preceding "):])
	if err != nil {
		return nil, fmt.Errorf("invalid preceding size: %w", err)
	}
	var compactRange [][sha256.Size]byte
	for i := 2; i < len(headerLines); i++ {
		hB64 := headerLines[i]
		if len(hB64) != 44 {
			return nil, fmt.Errorf("invalid compact range hash length in line %d", i)
		}
		hBytes, err := strictBase64.DecodeString(hB64)
		if err != nil || len(hBytes) != sha256.Size {
			return nil, fmt.Errorf("invalid compact range hash in line %d", i)
		}
		var h [sha256.Size]byte
		copy(h[:], hBytes)
		compactRange = append(compactRange, h)
	}
	if len(compactRange) != bits.OnesCount64(preceding) {
		return nil, fmt.Errorf("compact range hash count %d does not match popcount(preceding=%d)=%d", len(compactRange), preceding, bits.OnesCount64(preceding))
	}

	idxBlock := strings.TrimSuffix(string(parts[1]), "\n")
	if idxBlock == "" {
		return nil, errors.New("values response must contain at least one index")
	}
	idxLines := strings.Split(idxBlock, "\n")
	indices := make([]uint64, 0, len(idxLines))
	for i, line := range idxLines {
		idx, err := parseUint64Strict(line)
		if err != nil {
			return nil, fmt.Errorf("invalid entry index %q: %w", line, err)
		}
		if i > 0 && idx <= indices[i-1] {
			return nil, fmt.Errorf("entry indices not strictly ascending: %d followed by %d", indices[i-1], idx)
		}
		indices = append(indices, idx)
	}
	if preceding > indices[0] {
		return nil, fmt.Errorf("preceding count (%d) exceeds first entry index (%d)", preceding, indices[0])
	}
	return &ValuesSection{
		Preceding:    preceding,
		CompactRange: compactRange,
		Indices:      indices,
	}, nil
}

var emptyRoot = sha256.Sum256(nil)

// EmptyRoot returns the RFC 6962 root hash of an empty tree (SHA256("")).
func EmptyRoot() [sha256.Size]byte {
	return emptyRoot
}

// LeafHash computes the RFC 6962 standard leaf hash: SHA256(0x00 || data).
// For leaves up to 511 bytes (including all 8-byte index leaves in VIndex),
// an inline stack buffer avoids heap allocations.
func LeafHash(data []byte) [sha256.Size]byte {
	if len(data) <= 511 {
		var b [512]byte
		b[0] = 0x00
		copy(b[1:], data)
		return sha256.Sum256(b[:1+len(data)])
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

// InteriorHash computes the RFC 6962 standard interior node hash: SHA256(0x01 || left || right).
func InteriorHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	var b [1 + 2*sha256.Size]byte
	b[0] = 0x01
	copy(b[1:], left[:])
	copy(b[1+sha256.Size:], right[:])
	return sha256.Sum256(b[:])
}

// ComputeValueLogRoot reconstructs the RFC 6962 value log root from a preceding compact range
// and a slice of strictly ascending uint64 leaf indices.
func ComputeValueLogRoot(compactRange [][sha256.Size]byte, preceding uint64, indices []uint64) ([sha256.Size]byte, error) {
	if len(compactRange) != bits.OnesCount64(preceding) {
		return [sha256.Size]byte{}, fmt.Errorf("mismatched compact range: preceding=%d (popcount=%d), hashes=%d", preceding, bits.OnesCount64(preceding), len(compactRange))
	}
	if len(indices) > 0 {
		if preceding > indices[0] {
			return [sha256.Size]byte{}, fmt.Errorf("preceding count (%d) exceeds first entry index (%d)", preceding, indices[0])
		}
		if uint64(len(indices)) > math.MaxUint64-preceding {
			return [sha256.Size]byte{}, errors.New("value log leaf count overflows uint64")
		}
		for i := 1; i < len(indices); i++ {
			if indices[i] <= indices[i-1] {
				return [sha256.Size]byte{}, fmt.Errorf("entry indices not strictly ascending: %d followed by %d", indices[i-1], indices[i])
			}
		}
	}
	if len(compactRange) == 0 && len(indices) == 0 {
		return EmptyRoot(), nil
	}

	rf := &compact.RangeFactory{
		Hash: func(l, r []byte) []byte {
			if len(l) == sha256.Size && len(r) == sha256.Size {
				var left, right [sha256.Size]byte
				copy(left[:], l)
				copy(right[:], r)
				h := InteriorHash(left, right)
				out := make([]byte, sha256.Size)
				copy(out, h[:])
				return out
			}
			return rfc6962.DefaultHasher.HashChildren(l, r)
		},
	}

	var cr *compact.Range
	if preceding > 0 {
		hashes := make([][]byte, len(compactRange))
		for i := range compactRange {
			hashes[i] = compactRange[i][:]
		}
		var err error
		cr, err = rf.NewRange(0, preceding, hashes)
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("invalid compact range: %w", err)
		}
	} else {
		cr = rf.NewEmptyRange(0)
	}

	for _, idx := range indices {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		lh := LeafHash(b[:])
		if err := cr.Append(lh[:], nil); err != nil {
			return [sha256.Size]byte{}, err
		}
	}

	r, err := cr.GetRootHash(nil)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var root [sha256.Size]byte
	copy(root[:], r)
	return root, nil
}
