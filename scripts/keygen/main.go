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
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

func validOrigin(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func main() {
	origin := "vindex.local"
	if len(os.Args) > 1 {
		arg := strings.TrimSpace(os.Args[1])
		if arg == "-h" || arg == "--help" {
			fmt.Println("Usage: go run ./scripts/keygen [origin]")
			return
		}
		if arg != "" {
			origin = arg
		}
	}
	if !validOrigin(origin) {
		fmt.Fprintf(os.Stderr, "Invalid origin %q: must be printable ASCII without leading/trailing spaces\n", origin)
		os.Exit(1)
	}

	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Origin:       %s\n", origin)
	fmt.Printf("Signer Key:   %s\n", skey)
	fmt.Printf("Verifier Key: %s\n", vkey)
}
