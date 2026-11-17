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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o mtc.wasm ."

// Package main implements the MTC (Merkle Tree Certificates) WASM MapFn plugin.
package main

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
	"golang.org/x/net/idna"
)

var (
	oidCommonName     = []byte{0x55, 0x04, 0x03}
	oidSubjectAltName = []byte{0x55, 0x1d, 0x11}
)

func main() {}

func init() {
	sdk.RegisterEmit(MapMTCLeaf)
}

func readTagLen(b []byte) (tag byte, content []byte, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if b[1] < 0x80 {
		l := int(b[1])
		if l > len(b)-2 {
			return 0, nil, nil, false
		}
		return tag, b[2 : 2+l], b[2+l:], true
	}
	numBytes := int(b[1] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
		return 0, nil, nil, false
	}
	var l int
	for i := range numBytes {
		l = (l << 8) | int(b[2+i])
	}
	// Subtract rather than add so 32-bit wasm int cannot overflow on l == MaxInt32.
	if l < 0 || l > len(b)-(2+numBytes) {
		return 0, nil, nil, false
	}
	end := 2 + numBytes + l
	return tag, b[2+numBytes : end], b[end:], true
}

func extractDNSNamesFromDER(der []byte, emit func(item []byte)) {
	tag, tbsContent, _, ok := readTagLen(der)
	if !ok || tag != 0x30 {
		return
	}

	seqCount := 0
	for len(tbsContent) > 0 {
		var field []byte
		tag, field, tbsContent, ok = readTagLen(tbsContent)
		if !ok {
			return
		}
		if tag == 0x30 {
			seqCount++
			if seqCount == 3 { // 3rd SEQUENCE in TBSCertificateLogEntry is Subject
				subjSeq := field
				for len(subjSeq) > 0 {
					var rdnSet []byte
					tag, rdnSet, subjSeq, ok = readTagLen(subjSeq)
					if !ok || tag != 0x31 {
						break
					}
					for len(rdnSet) > 0 {
						var attrSeq []byte
						tag, attrSeq, rdnSet, ok = readTagLen(rdnSet)
						if !ok || tag != 0x30 {
							break
						}
						oTag, oid, attrRest, ok := readTagLen(attrSeq)
						if ok && oTag == 0x06 && bytes.Equal(oid, oidCommonName) {
							_, val, _, ok := readTagLen(attrRest)
							if ok && len(val) > 0 {
								emit(val)
							}
						}
					}
				}
			}
			continue
		}
		if tag == 0xa3 && seqCount >= 3 { // [3] EXPLICIT Extensions (follows Subject)
			tag, extSeq, _, ok := readTagLen(field)
			if !ok || tag != 0x30 {
				return
			}
			for len(extSeq) > 0 {
				var ext []byte
				tag, ext, extSeq, ok = readTagLen(extSeq)
				if !ok || tag != 0x30 {
					return
				}
				tag, oid, ext, ok := readTagLen(ext)
				if !ok || tag != 0x06 || !bytes.Equal(oid, oidSubjectAltName) {
					continue
				}
				tag, val, ext, ok := readTagLen(ext)
				if !ok {
					return
				}
				if tag == 0x01 { // critical BOOLEAN
					tag, val, _, ok = readTagLen(ext)
					if !ok {
						return
					}
				}
				if tag != 0x04 { // extnValue OCTET STRING
					return
				}
				tag, sanSeq, _, ok := readTagLen(val)
				if !ok || tag != 0x30 {
					return
				}
				for len(sanSeq) > 0 {
					var item []byte
					tag, item, sanSeq, ok = readTagLen(sanSeq)
					if !ok {
						return
					}
					if tag == 0x82 { // [2] IMPLICIT dNSName
						emit(item)
					}
				}
				return
			}
		}
	}
}

func canonicalizeDomainBytes(raw []byte, outBuf *[256]byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[len(raw)-1] == '.' {
		raw = raw[:len(raw)-1]
	}
	// Multi-label UTF-8 IDNs can exceed 253 UTF-8 bytes before Punycode compression;
	// the strict 253-octet RFC 1035 wire limit is enforced after IDNA conversion below.
	if len(raw) == 0 || len(raw) > 1024 {
		return nil, false
	}

	hasWildcard := false
	if len(raw) >= 2 && raw[0] == '*' && raw[1] == '.' {
		hasWildcard = true
		raw = raw[2:]
	} else if raw[0] == '*' {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, false
	}

	hasNonASCII := false
	for i := range raw {
		if raw[i] >= 0x80 {
			hasNonASCII = true
			break
		}
	}
	if hasNonASCII {
		ascii, err := idna.Lookup.ToASCII(string(raw))
		if err != nil || len(ascii) == 0 {
			return nil, false
		}
		if ascii[len(ascii)-1] == '.' {
			ascii = ascii[:len(ascii)-1]
		}
		if len(ascii) == 0 {
			return nil, false
		}
		raw = []byte(ascii)
	}

	needed := len(raw) + 1
	if hasWildcard {
		needed += 2
	}
	if needed-1 > 253 || needed > len(outBuf) {
		return nil, false
	}

	outLen := 0
	dotCount := 0
	labelEnd := len(raw)

	for i := len(raw) - 1; i >= -1; i-- {
		if i == -1 || raw[i] == '.' {
			if i >= 0 {
				dotCount++
			}
			labelStart := i + 1
			labelLen := labelEnd - labelStart
			if labelLen < 1 || labelLen > 63 {
				return nil, false
			}
			if raw[labelStart] == '-' || raw[labelEnd-1] == '-' {
				return nil, false
			}
			isTLD := labelEnd == len(raw)
			allDigits := true
			for j := labelStart; j < labelEnd; j++ {
				c := raw[j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
					return nil, false
				}
				if c < '0' || c > '9' {
					allDigits = false
				}
				outBuf[outLen] = c
				outLen++
			}
			if isTLD && allDigits {
				return nil, false
			}
			outBuf[outLen] = '.'
			outLen++
			labelEnd = i
		}
	}

	if dotCount < 1 {
		return nil, false
	}
	if hasWildcard {
		outBuf[outLen] = '*'
		outLen++
		outBuf[outLen] = '.'
		outLen++
	}
	return outBuf[:outLen], true
}

type domainSpan struct {
	start uint16
	end   uint16
}

// Static storage buffers for zero-allocation domain processing within the single-threaded
// WASM guest, guarded by CAS with a stack fallback for concurrent native Go callers.
var (
	leafScratchInUse uint32
	leafStorage      [2048]byte
	leafSpans        [64]domainSpan
)

// MapMTCLeaf extracts all unique reversed-label canonical domain keys from an MTC log leaf.
func MapMTCLeaf(leaf []byte, emit func(key []byte)) {
	if len(leaf) < 2 {
		return
	}
	entryType := binary.BigEndian.Uint16(leaf[:2])
	if entryType != 1 {
		return
	}

	storage := &leafStorage
	spans := &leafSpans
	if atomic.CompareAndSwapUint32(&leafScratchInUse, 0, 1) {
		defer atomic.StoreUint32(&leafScratchInUse, 0)
	} else {
		var localStorage [2048]byte
		var localSpans [64]domainSpan
		storage = &localStorage
		spans = &localSpans
	}

	storageUsed := 0
	spanCount := 0
	var overflowDomains [][]byte
	var outBuf [256]byte

	extractDNSNamesFromDER(leaf[2:], func(item []byte) {
		canon, ok := canonicalizeDomainBytes(item, &outBuf)
		if !ok {
			return
		}

		for i := range spanCount {
			sp := spans[i]
			if bytes.Equal(storage[sp.start:sp.end], canon) {
				return
			}
		}
		for _, ov := range overflowDomains {
			if bytes.Equal(ov, canon) {
				return
			}
		}

		if storageUsed+len(canon) <= len(storage) && spanCount < len(spans) {
			baseStart := uint16(storageUsed)
			baseEnd := baseStart + uint16(len(canon))
			copy(storage[baseStart:], canon)
			storageUsed = int(baseEnd)
			spans[spanCount] = domainSpan{start: baseStart, end: baseEnd}
			spanCount++
		} else {
			overflowDomains = append(overflowDomains, bytes.Clone(canon))
		}
	})

	for i := range spanCount {
		sp := spans[i]
		emit(storage[sp.start:sp.end])
	}
	for _, ov := range overflowDomains {
		emit(ov)
	}
}
