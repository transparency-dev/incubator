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
	"flag"
	"fmt"
	"os"
	"strings"

	fnote "github.com/transparency-dev/formats/note"
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

func generateKeypair(alg, origin string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "", "ed25519":
		return note.GenerateKey(rand.Reader, origin)
	case "mldsa44":
		return fnote.GenerateMLDSAKey(origin)
	default:
		return "", "", fmt.Errorf("unsupported key algorithm %q (expected \"ed25519\" or \"mldsa44\")", alg)
	}
}

func main() {
	alg := flag.String("alg", "ed25519", "Key algorithm: \"ed25519\" or \"mldsa44\".")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: go run ./scripts/keygen [-alg=ed25519|mldsa44] [origin]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Flag parsing stops at the first positional argument, so a flag placed
	// after the origin would otherwise be silently ignored.
	if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "Unexpected arguments %q: flags must come before the origin\n", flag.Args()[1:])
		flag.Usage()
		os.Exit(2)
	}

	origin := "vindex.local"
	if arg := strings.TrimSpace(flag.Arg(0)); arg != "" {
		origin = arg
	}
	if !validOrigin(origin) {
		fmt.Fprintf(os.Stderr, "Invalid origin %q: must be printable ASCII without leading/trailing spaces\n", origin)
		os.Exit(1)
	}

	skey, vkey, err := generateKeypair(*alg, origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Origin:       %s\n", origin)
	fmt.Printf("Algorithm:    %s\n", *alg)
	fmt.Printf("Signer Key:   %s\n", skey)
	fmt.Printf("Verifier Key: %s\n", vkey)
}
