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
	"fmt"
	"testing"
)

func TestMapSumDBLeaf_StandardRelease(t *testing.T) {
	leaf := []byte("golang.org/x/mod v0.40.0 h1:testHash123=\ngolang.org/x/mod v0.40.0/go.mod h1:testHash456=\n")
	var keys [][]byte
	MapSumDBLeaf(leaf, func(key []byte) {
		keys = append(keys, key)
	})

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if string(keys[0]) != "golang.org/x/mod" {
		t.Fatalf("key mismatch: got %q, want %q", string(keys[0]), "golang.org/x/mod")
	}
}

func TestMapSumDBLeaf_PseudoVersionFiltered(t *testing.T) {
	leaf := []byte(
		"github.com/example/repo v0.0.0-20230101000000-0123456789ab h1:testHash=\n" +
			"github.com/example/repo2 v1.2.4-0.20190528180746-1234567890ab+incompatible h1:testHash=\n" +
			"github.com/example/repo3 v1.2.3-pre.0.20190528180746-1234567890ab h1:testHash=\n",
	)
	var keys [][]byte
	MapSumDBLeaf(leaf, func(key []byte) {
		keys = append(keys, key)
	})

	if len(keys) != 0 {
		t.Fatalf("expected 0 keys for pseudo-versions, got %d", len(keys))
	}
}

func TestMapSumDBLeaf_MultipleModulesInSingleLeaf(t *testing.T) {
	leaf := []byte("github.com/mod1 v1.0.0 h1:h1=\ngithub.com/mod2/v2 v2.1.0 h1:h2=\n")
	var keys [][]byte
	MapSumDBLeaf(leaf, func(key []byte) {
		keys = append(keys, key)
	})

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if string(keys[0]) != "github.com/mod1" || string(keys[1]) != "github.com/mod2/v2" {
		t.Fatalf("keys mismatch: got %q, %q", string(keys[0]), string(keys[1]))
	}
}

func TestMapSumDBLeaf_MoreThan8Modules(t *testing.T) {
	var buf []byte
	for i := 0; i < 12; i++ {
		buf = append(buf, fmt.Sprintf("github.com/mod%d v1.0.0 h1:h%d=\n", i, i)...)
	}
	var keys [][]byte
	MapSumDBLeaf(buf, func(key []byte) {
		keys = append(keys, key)
	})

	if len(keys) != 12 {
		t.Fatalf("expected 12 keys, got %d", len(keys))
	}
	for i := 0; i < 12; i++ {
		want := fmt.Sprintf("github.com/mod%d", i)
		if string(keys[i]) != want {
			t.Errorf("keys[%d] = %q, want %q", i, string(keys[i]), want)
		}
	}
}

func TestMapSumDBLeaf_EmptyOrMalformed(t *testing.T) {
	testCases := [][]byte{
		nil,
		[]byte(""),
		[]byte("   \n\n  "),
		[]byte("invalidline_without_spaces"),
		[]byte("golang.org/x/mod v0.40.0"),                // missing third (hash) field
		[]byte("golang.org/x/mod not-a-version h1:abc="),  // invalid semver
		[]byte("github.com/foo/bar/v1 v1.0.0 h1:abc="),    // disallowed /v1 suffix in module path
		[]byte("example.com/con v1.0.0 h1:abc="),          // disallowed Windows reserved path element
	}

	for _, tc := range testCases {
		var res [][]byte
		MapSumDBLeaf(tc, func(key []byte) {
			res = append(res, key)
		})
		if len(res) != 0 {
			t.Fatalf("expected 0 results for input %q, got %d (%q)", string(tc), len(res), res)
		}
	}
}

func TestMapSumDBLeaf_EscapePathAndValidation(t *testing.T) {
	leaf := []byte(
		"github.com/Azure/azure-sdk-for-go v1.0.0 h1:abc=\n" +
			"github.com/Azure/azure-sdk-for-go v1.0.0/go.mod h1:def=\n" +
			"invalid_no_dot_module v1.0.0 h1:bad=\n",
	)
	var keys []string
	MapSumDBLeaf(leaf, func(key []byte) {
		keys = append(keys, string(key))
	})

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d (%v)", len(keys), keys)
	}
	want := "github.com/!azure/azure-sdk-for-go"
	if keys[0] != want {
		t.Errorf("got %q, want %q", keys[0], want)
	}
}

func BenchmarkMapSumDBLeaf(b *testing.B) {
	leaf := []byte("golang.org/x/mod v0.40.0 h1:testHash123=\ngolang.org/x/mod v0.40.0/go.mod h1:testHash456=\n")
	b.ReportAllocs()

	emitSink := func(key []byte) {}
	for b.Loop() {
		MapSumDBLeaf(leaf, emitSink)
	}
}
