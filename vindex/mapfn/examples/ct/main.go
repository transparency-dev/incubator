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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o ct.wasm ."

// Package main implements an optimized, zero-alloc CT (Certificate Transparency) WASM MapFn plugin.
package main

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
	"golang.org/x/net/idna"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapCTLeaf)
}

var (
	oidSANRaw = []byte{0x55, 0x1d, 0x11} // 2.5.29.17 (Subject Alternative Name)
	oidCNRaw  = []byte{0x55, 0x04, 0x03} // 2.5.4.3 (Common Name)
)

type domainSpan struct {
	start uint16
	end   uint16
}

// Package-level scratch buffers avoid a 2 KB heap allocation per leaf: slicing a local
// array into the indirect `emit func([]byte)` parameter causes Go's escape analysis
// to move the backing array to the heap.
var (
	leafScratchInUse uint32
	leafStorage      [2048]byte
	leafSpans        [64]domainSpan
)

// MapCTLeaf extracts all unique reversed-label canonical domain keys from a CT log leaf.
func MapCTLeaf(data []byte, emit func(key []byte)) {
	if len(data) == 0 {
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

	extractRawDomainNames(data, func(rawName []byte) {
		canon, ok := canonicalizeDomainBytes(rawName, &outBuf)
		if !ok {
			return
		}

		for i := 0; i < spanCount; i++ {
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
			overflowDomains = append(overflowDomains, append([]byte(nil), canon...))
		}
	})

	for i := 0; i < spanCount; i++ {
		sp := spans[i]
		emit(storage[sp.start:sp.end])
	}
	for _, ov := range overflowDomains {
		emit(ov)
	}
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func canonicalizeDomainBytes(raw []byte, outBuf *[256]byte) ([]byte, bool) {
	for len(raw) > 0 && isASCIIWhitespace(raw[0]) {
		raw = raw[1:]
	}
	for len(raw) > 0 && isASCIIWhitespace(raw[len(raw)-1]) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) > 0 && raw[len(raw)-1] == '.' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 {
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
	for i := 0; i < len(raw); i++ {
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
	if len(raw) > 253 || needed > len(outBuf) {
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

// readASN1Header parses tag and length at pos. Returns (tag, contentStart, contentEnd, ok).
func readASN1Header(b []byte, pos int) (tag byte, start, end int, ok bool) {
	if pos < 0 || pos >= len(b) {
		return 0, 0, 0, false
	}
	tag = b[pos]
	pos++
	if pos >= len(b) {
		return 0, 0, 0, false
	}
	lByte := b[pos]
	pos++
	var length int
	if lByte < 0x80 {
		length = int(lByte)
	} else {
		numBytes := int(lByte & 0x7f)
		if numBytes == 0 || numBytes > 4 || numBytes > len(b)-pos {
			return 0, 0, 0, false
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(b[pos+i])
		}
		pos += numBytes
	}
	if length < 0 || length > len(b)-pos {
		return 0, 0, 0, false
	}
	return tag, pos, pos + length, true
}

// fastExtractDomainsFromTBS extracts CommonName and SAN DNSNames from raw TBSCertificate DER.
func fastExtractDomainsFromTBS(tbs []byte, emit func(raw []byte)) bool {
	tag, start, end, ok := readASN1Header(tbs, 0)
	if !ok || tag != 0x30 || end != len(tbs) {
		return false
	}
	payload := tbs[start:end]

	pos := 0

	// 1. Optional version [0] EXPLICIT
	if pos < len(payload) && payload[pos] == 0xa0 {
		_, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// 2. serialNumber INTEGER (0x02)
	if tag, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x02 {
		pos = next
	} else {
		return false
	}

	// 3. signature AlgorithmIdentifier SEQUENCE (0x30)
	if tag, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 4. issuer Name SEQUENCE (0x30)
	if tag, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 5. validity Validity SEQUENCE (0x30)
	if tag, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// 6. subject Name SEQUENCE (0x30)
	var subjectBytes []byte
	if tag, sStart, sEnd, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = sEnd
		subjectBytes = payload[sStart:sEnd]
	} else {
		return false
	}

	// 7. subjectPublicKeyInfo SEQUENCE (0x30) - SKIP without parsing keys!
	if tag, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return false
	}

	// Optional: issuerUniqueID [1]
	if pos < len(payload) && payload[pos] == 0x81 {
		_, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// Optional: subjectUniqueID [2]
	if pos < len(payload) && payload[pos] == 0x82 {
		_, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return false
		}
		pos = next
	}

	// Emit Subject CN if present
	sPos := 0
	for sPos < len(subjectBytes) {
		_, setStart, setEnd, ok := readASN1Header(subjectBytes, sPos)
		if !ok {
			break
		}
		setBytes := subjectBytes[setStart:setEnd]
		subPos := 0
		for subPos < len(setBytes) {
			_, seqStart, seqEnd, ok := readASN1Header(setBytes, subPos)
			if !ok {
				break
			}
			seqBytes := setBytes[seqStart:seqEnd]
			oTag, oStart, oEnd, ok := readASN1Header(seqBytes, 0)
			if ok && oTag == 0x06 && bytes.Equal(seqBytes[oStart:oEnd], oidCNRaw) {
				_, vStart, vEnd, ok := readASN1Header(seqBytes, oEnd)
				if ok && vEnd > vStart {
					emit(seqBytes[vStart:vEnd])
				}
			}
			subPos = seqEnd
		}
		sPos = setEnd
	}

	// Optional: extensions [3] EXPLICIT (0xa3)
	if pos < len(payload) && payload[pos] == 0xa3 {
		_, eStart, eEnd, ok := readASN1Header(payload, pos)
		if ok {
			extContainer := payload[eStart:eEnd]
			tag, sStart, sEnd, ok := readASN1Header(extContainer, 0)
			if ok && tag == 0x30 {
				extList := extContainer[sStart:sEnd]
				ePos := 0
				for ePos < len(extList) {
					_, itemStart, itemEnd, ok := readASN1Header(extList, ePos)
					if !ok {
						break
					}
					itemBytes := extList[itemStart:itemEnd]
					iPos := 0
					tag, oStart, oEnd, ok := readASN1Header(itemBytes, iPos)
					if ok && tag == 0x06 {
						isSAN := bytes.Equal(itemBytes[oStart:oEnd], oidSANRaw)
						iPos = oEnd
						if iPos < len(itemBytes) && itemBytes[iPos] == 0x01 { // critical BOOLEAN
							_, _, next, ok := readASN1Header(itemBytes, iPos)
							if ok {
								iPos = next
							}
						}
						tag, vStart, vEnd, ok := readASN1Header(itemBytes, iPos) // extnValue OCTET STRING
						if ok && tag == 0x04 && isSAN {
							sanVal := itemBytes[vStart:vEnd]
							tag, gnStart, gnEnd, ok := readASN1Header(sanVal, 0)
							if ok && tag == 0x30 {
								gnList := sanVal[gnStart:gnEnd]
								gnPos := 0
								for gnPos < len(gnList) {
									tag, dStart, dEnd, ok := readASN1Header(gnList, gnPos)
									if !ok {
										break
									}
									if tag == 0x82 && dEnd > dStart { // dNSName [2]
										emit(gnList[dStart:dEnd])
									}
									gnPos = dEnd
								}
							}
						}
					}
					ePos = itemEnd
				}
			}
		}
	}

	return true
}

// fastExtractDomainsFromCert unwraps the outer Certificate SEQUENCE and parses TBSCertificate.
func fastExtractDomainsFromCert(certDer []byte, emit func(raw []byte)) bool {
	tag, start, end, ok := readASN1Header(certDer, 0)
	if !ok || tag != 0x30 || end != len(certDer) {
		return false
	}
	outer := certDer[start:end]
	tag, _, tbsEnd, ok := readASN1Header(outer, 0)
	if !ok || tag != 0x30 {
		return false
	}
	return fastExtractDomainsFromTBS(outer[:tbsEnd], emit)
}

func extractRawDomainNames(data []byte, emit func(raw []byte)) {
	if len(data) == 0 {
		return
	}

	// 1. Try RFC 6962 MerkleTreeLeaf parsing (starts with 0x00, 0x00 version & leaf_type,
	//    and ends with a 2-byte extensions length matching len(data)).
	if len(data) >= 17 && data[0] == 0 && data[1] == 0 {
		entryType := binary.BigEndian.Uint16(data[10:12])
		if entryType == 0 { // x509_entry
			certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
			if certLen > 0 && len(data) >= 17+certLen {
				extLen := int(binary.BigEndian.Uint16(data[15+certLen : 17+certLen]))
				if 17+certLen+extLen == len(data) && fastExtractDomainsFromCert(data[15:15+certLen], emit) {
					return
				}
			}
		} else if entryType == 1 && len(data) >= 49 { // precert_entry
			tbsLen := int(data[44])<<16 | int(data[45])<<8 | int(data[46])
			if tbsLen > 0 && len(data) >= 49+tbsLen {
				extLen := int(binary.BigEndian.Uint16(data[47+tbsLen : 49+tbsLen]))
				if 49+tbsLen+extLen == len(data) && fastExtractDomainsFromTBS(data[47:47+tbsLen], emit) {
					return
				}
			}
		}
	}

	// 2. Try C2SP Static-CT TileLeaf parsing (starts directly with 8-byte timestamp)
	if len(data) >= 13 {
		entryType := binary.BigEndian.Uint16(data[8:10])
		if entryType == 0 { // x509_entry
			certLen := int(data[10])<<16 | int(data[11])<<8 | int(data[12])
			if certLen > 0 && len(data) >= 13+certLen {
				if fastExtractDomainsFromCert(data[13:13+certLen], emit) {
					return
				}
			}
		} else if entryType == 1 && len(data) >= 45 { // precert_entry
			tbsLen := int(data[42])<<16 | int(data[43])<<8 | int(data[44])
			if tbsLen > 0 && len(data) >= 45+tbsLen {
				if fastExtractDomainsFromTBS(data[45:45+tbsLen], emit) {
					return
				}
			}
		}
	}

	// 3. Try raw X.509 Certificate DER
	if fastExtractDomainsFromCert(data, emit) {
		return
	}

	// 4. Try raw TBSCertificate DER
	_ = fastExtractDomainsFromTBS(data, emit)
}
