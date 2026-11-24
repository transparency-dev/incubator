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
	"testing"

	fnote "github.com/transparency-dev/formats/note"
)

func TestGenerateKeypair(t *testing.T) {
	for _, alg := range []string{"ed25519", "mldsa44"} {
		skey, vkey, err := generateKeypair(alg, "vindex.test")
		if err != nil {
			t.Fatalf("generateKeypair(%q) failed: %v", alg, err)
		}
		if _, err := fnote.NewSigner(skey); err != nil {
			t.Fatalf("fnote.NewSigner(%q) failed: %v", alg, err)
		}
		if _, err := fnote.NewVerifier(vkey); err != nil {
			t.Fatalf("fnote.NewVerifier(%q) failed: %v", alg, err)
		}
	}
	if _, _, err := generateKeypair("rsa", "vindex.test"); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
