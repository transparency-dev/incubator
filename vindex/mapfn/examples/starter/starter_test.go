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
	"testing"
)

func TestMapLeaf(t *testing.T) {
	input := []byte("sample leaf entry")
	var keys [][]byte
	MapLeaf(input, func(key []byte) {
		for i, b := range key {
			if b < 0x21 || b > 0x7E {
				t.Fatalf("emitted non-canonical byte 0x%02x at offset %d", b, i)
			}
		}
		keys = append(keys, append([]byte(nil), key...))
	})
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	want := []byte("sample_leaf_entry")
	if !bytes.Equal(keys[0], want) {
		t.Fatalf("expected key %q, got %q", string(want), string(keys[0]))
	}
}

func TestMapLeaf_Empty(t *testing.T) {
	var count int
	emitCount := func(key []byte) { count++ }

	count = 0
	MapLeaf(nil, emitCount)
	if count != 0 {
		t.Fatalf("expected 0 keys for nil input, got %d", count)
	}

	count = 0
	MapLeaf([]byte("   \n\t  "), emitCount)
	if count != 0 {
		t.Fatalf("expected 0 keys for whitespace input, got %d", count)
	}
}

