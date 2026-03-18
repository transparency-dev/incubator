package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

var exampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var pseudoVersionLeaf = []byte(`github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356 h1:4jV/qA6RzP7Z6s+/vQ0W2RjM3FjC6B2M3r8=
github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356/go.mod h1:T/Ym+5H1e28Qv6iMzT3w=
`)

var releaseCandidateLeaf = []byte(`github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1 h1:f1nwnVa7t5Ftd+BPef/V/Y8XxT1Sdiif0cdIo/8R9i0=
github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1/go.mod h1:CuxOEw4CmUSK44owsXWkZ6Njh0G/gfboQoLl9hn1Voo=`)

func TestMapFn(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf []byte
		want [][32]byte
	}{
		{
			name: "valid",
			leaf: exampleLeaf,
			want: [][32]byte{sha256.Sum256([]byte("golang.org/x/text"))},
		},
		{
			name: "pseudo_version",
			leaf: pseudoVersionLeaf,
			want: nil,
		},
		{
			name: "release_candidate",
			leaf: releaseCandidateLeaf,
			want: [][32]byte{sha256.Sum256([]byte("github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapFn(tc.leaf)
			if len(got) != len(tc.want) {
				t.Fatalf("mapFn() returned %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !bytes.Equal(got[i][:], tc.want[i][:]) {
					t.Errorf("mapFn()[%d] = %x, want %x", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func BenchmarkMapFn(b *testing.B) {
	for b.Loop() {
		mapFn(exampleLeaf)
		mapFn(pseudoVersionLeaf)
		mapFn(releaseCandidateLeaf)
	}
}
