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

package tree

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type fakeOutputLog struct {
	mu          sync.Mutex
	origin      string
	signers     []note.Signer
	leaves      [][]byte
	onAppend    func() error
	forceIdx    *uint64
	proofErr    error
}

func (f *fakeOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	if f.onAppend != nil {
		if err := f.onAppend(); err != nil {
			return 0, nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	idx := uint64(len(f.leaves))
	f.leaves = append(f.leaves, leafData)
	dummyRoot := sha256.Sum256(leafData)
	body := fmt.Sprintf("%s\n%d\n%s\n", f.origin, len(f.leaves), base64.StdEncoding.EncodeToString(dummyRoot[:]))

	var rawCP []byte
	if len(f.signers) > 0 {
		var err error
		rawCP, err = note.Sign(&note.Note{Text: body}, f.signers...)
		if err != nil {
			return 0, nil, err
		}
	} else {
		rawCP = []byte(body + "\n\xe2\x80\x94 test_sig\n")
	}
	if f.forceIdx != nil {
		idx = *f.forceIdx
	}
	return idx, rawCP, nil
}

func (f *fakeOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	if f.proofErr != nil {
		return nil, f.proofErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if leafIdx >= uint64(len(f.leaves)) || treeSize > uint64(len(f.leaves)) {
		return nil, fmt.Errorf("invalid leafIdx %d or treeSize %d", leafIdx, treeSize)
	}
	if treeSize > 1 {
		return [][sha256.Size]byte{sha256.Sum256([]byte("sibling_hash"))}, nil
	}
	return nil, nil
}

func TestPublisher_PublishProgressionAndBootstrap(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := &fakeOutputLog{origin: "example.com/outputlog"}
	pub := NewOutputPublisher(mptMgr, outLog)

	emptyHash := wire.EmptyRoot()
	h100 := sha256.Sum256([]byte("in-100"))
	h200 := sha256.Sum256([]byte("in-200"))

	// 1. Bootstrap empty commitment (size == 0, from == 0, EmptyRoot)
	st0, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   0,
		Hash:   emptyHash[:],
	})
	if err != nil || st0.OutputLogIndex != 0 || st0.MPTRoot != emptyHash {
		t.Fatalf("bootstrap PublishKeyBatch: st=%+v err=%v", st0, err)
	}
	parsedLeaf0, err := wire.ParseOutputLogLeafFull(outLog.leaves[0])
	if err != nil || parsedLeaf0.From != 0 || parsedLeaf0.InCP.Size != 0 || parsedLeaf0.MPTRoot != emptyHash {
		t.Fatalf("ParseOutputLogLeafFull(0) = %+v err=%v", parsedLeaf0, err)
	}

	// 2. Advance to size 100 with key1
	key1 := "com.google.mail."
	val1 := sha256.Sum256([]byte("val1"))
	st1, err := pub.PublishKeyBatch(ctx, map[string][32]byte{key1: val1}, &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   100,
		Hash:   h100[:],
	})
	if err != nil || st1.OutputLogIndex != 1 || st1.InputLogSize != 100 {
		t.Fatalf("PublishKeyBatch(100): st=%+v err=%v", st1, err)
	}
	proof, val, exists, err := mptMgr.ProveKey([]byte(key1))
	if err != nil || !exists || val != val1 {
		t.Fatalf("ProveKey(%q): exists=%v val=%x err=%v", key1, exists, val, err)
	}
	if err := mpt.VerifyKey(st1.MPTRoot, []byte(key1), val, true, proof); err != nil {
		t.Fatalf("VerifyKey(%q) failed: %v", key1, err)
	}

	// 3. Advance to size 200 with zero modified keys (empty batch preserves MPT root)
	st2, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   200,
		Hash:   h200[:],
	})
	if err != nil || st2.OutputLogIndex != 2 || st2.MPTRoot != st1.MPTRoot {
		t.Fatalf("PublishKeyBatch(200 empty muts): st=%+v err=%v", st2, err)
	}

	// 4. Non-zero from bootstrap (from == 500, size == 500)
	pubFrom := NewOutputPublisher(mpt.NewMem(), &fakeOutputLog{origin: "example.com/outputlog"})
	pubFrom.SetFrom(500)
	stFrom, err := pubFrom.PublishKeyBatch(ctx, nil, &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   500,
		Hash:   h100[:],
	})
	if err != nil || stFrom.From != 500 || stFrom.MPTRoot != emptyHash {
		t.Fatalf("PublishKeyBatch(from=500, size=500): st=%+v err=%v", stFrom, err)
	}
}

func TestPublishKeyBatch_RootPredictionMismatch_Panics(t *testing.T) {
	ctx := context.Background()
	mptMgr := mpt.NewMem()
	outLog := &fakeOutputLog{
		origin: "example.com/outputlog",
		onAppend: func() error {
			sneakVal := sha256.Sum256([]byte("sneaky_interfering_val"))
			_, err := mptMgr.CommitKeysWithVersion(map[string][32]byte{"com.example.sneaky.": sneakVal}, 1)
			return err
		},
	}
	pub := NewOutputPublisher(mptMgr, outLog)

	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprintf("%v", r), "prediction mismatch") {
			t.Fatalf("expected prediction mismatch panic, got %v", r)
		}
	}()

	h := sha256.Sum256([]byte("in"))
	_, _ = pub.PublishKeyBatch(ctx, map[string][32]byte{"com.example.key1.": sha256.Sum256([]byte("v1"))}, &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   h[:],
	})
}

func TestOutputPublisher_FailureInjectionAndConcurrentReaders(t *testing.T) {
	ctx := context.Background()
	h1 := sha256.Sum256([]byte("h1"))
	val1 := sha256.Sum256([]byte("val1"))

	// 1. Append failure leaves MPT untouched and ServingState nil
	mpt1 := mpt.NewMem()
	pubFailAppend := NewOutputPublisher(mpt1, &fakeOutputLog{
		origin:   "example.com/out",
		onAppend: func() error { return errors.New("append network failure") },
	})
	if _, err := pubFailAppend.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, &log.Checkpoint{
		Origin: "example.com/in", Size: 10, Hash: h1[:],
	}); err == nil {
		t.Fatal("expected error on Append failure")
	}
	if mpt1.Root() != wire.EmptyRoot() || !mpt1.IsExact() || pubFailAppend.GetServingState() != nil {
		t.Fatal("Append failure mutated MPT or ServingState")
	}

	// 2. InclusionProof failure leaves MPT untouched and ServingState nil
	mpt2 := mpt.NewMem()
	pubFailProof := NewOutputPublisher(mpt2, &fakeOutputLog{
		origin:   "example.com/out",
		proofErr: errors.New("proof read error"),
	})
	if _, err := pubFailProof.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, &log.Checkpoint{
		Origin: "example.com/in", Size: 10, Hash: h1[:],
	}); err == nil {
		t.Fatal("expected error on InclusionProof failure")
	}
	if mpt2.Root() != wire.EmptyRoot() || pubFailProof.GetServingState() != nil {
		t.Fatal("InclusionProof failure mutated MPT or ServingState")
	}

	// 3. Concurrent PublishKeyBatch + concurrent RLock/ProveKeyLocked readers under -race
	mpt3 := mpt.NewMem()
	pubConc := NewOutputPublisher(mpt3, &fakeOutputLog{origin: "example.com/out"})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				mpt3.RLock()
				st := pubConc.GetServingState()
				if st != nil {
					proof, vr, ok, err := mpt3.ProveKeyLocked([]byte("com.example.k0"))
					if err != nil {
						mpt3.RUnlock()
						t.Errorf("ProveKeyLocked failed: %v", err)
						return
					}
					if err := mpt.VerifyKey(st.MPTRoot, []byte("com.example.k0"), vr, ok, proof); err != nil {
						mpt3.RUnlock()
						t.Errorf("VerifyKey consistency race against ServingState: %v", err)
						return
					}
				}
				mpt3.RUnlock()
			}
		}
	}()

	for step := uint64(1); step <= 20; step++ {
		hs := sha256.Sum256([]byte(fmt.Sprintf("in-%d", step)))
		k := fmt.Sprintf("com.example.k%d", step-1)
		if _, err := pubConc.PublishKeyBatch(ctx, map[string][32]byte{k: sha256.Sum256([]byte(k))}, &log.Checkpoint{
			Origin: "example.com/in", Size: step * 10, Hash: hs[:],
		}); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("step %d PublishKeyBatch failed: %v", step, err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestCountWitnessSignatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{name: "unsigned_checkpoint", raw: "example.com/log\n1\nhash\n", want: 0},
		{name: "single_log_signature_only", raw: "example.com/log\n1\nhash\n\n— example.com/log sig0\n", want: 0},
		{name: "body_contains_signature_like_line", raw: "example.com/log\n1\nhash\n— body\n\n— example.com/log sig0\n", want: 0},
		{name: "log_plus_two_witnesses", raw: "example.com/log\n1\nhash\n\n— example.com/log sig0\n— witness.a sig1\n— witness.b sig2\n", want: 2},
	} {
		if got := countWitnessSignatures([]byte(tc.raw)); got != tc.want {
			t.Errorf("%s: countWitnessSignatures = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestOutputPublisher_SetOutputLogPolicyAndVerifyCheckpoint(t *testing.T) {
	ctx := context.Background()
	const outOrigin = "example.com/signed-outputlog"

	logSKey, logVKey, _ := note.GenerateKey(rand.Reader, outOrigin)
	logSigner, _ := note.NewSigner(logSKey)
	logVerifier, _ := note.NewVerifier(logVKey)

	witSKey, witVKey, _ := note.GenerateKey(rand.Reader, "witness.example/w1")
	witSigner, _ := note.NewSigner(witSKey)
	witVerifier, _ := note.NewVerifier(witVKey)

	pol, err := wire.BuildPolicy(outOrigin, logVerifier, []note.Verifier{witVerifier}, 1)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}

	inputCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: make([]byte, 32)}
	val1 := sha256.Sum256([]byte("val1"))

	// 1. Missing witness signature fails policy and VerifyCheckpoint
	pub1 := NewOutputPublisher(mpt.NewMem(), &fakeOutputLog{origin: outOrigin, signers: []note.Signer{logSigner}})
	pub1.SetOutputLogPolicy(pol)
	if _, err := pub1.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, inputCP); err == nil {
		t.Fatal("expected PublishKeyBatch to fail when required witness signature is missing")
	}
	if pub1.GetServingState() != nil {
		t.Fatal("expected nil serving state after witness policy failure")
	}

	// 2. Valid witness cosignature succeeds
	pub2 := NewOutputPublisher(mpt.NewMem(), &fakeOutputLog{origin: outOrigin, signers: []note.Signer{logSigner, witSigner}})
	pub2.SetOutputLogPolicy(pol)
	state, err := pub2.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, inputCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch with valid OutputLogPolicy failed: %v", err)
	}
	if _, err := pub2.VerifyCheckpoint(state.RawCheckpoint); err != nil {
		t.Fatalf("pub2.VerifyCheckpoint failed: %v", err)
	}
}

func TestOutputPublisher_ValidationAndMonotonicityGuards(t *testing.T) {
	ctx := context.Background()
	outLog := &fakeOutputLog{origin: "example.com/outputlog"}
	pub := NewOutputPublisher(mpt.NewMem(), outLog)

	pub.SetInputOrigin("example.com/inputlog")
	pub.SetFrom(50)
	if pub.InputOrigin() != "example.com/inputlog" || pub.From() != 50 {
		t.Fatal("InputOrigin/From accessor mismatch")
	}

	val1 := sha256.Sum256([]byte("val1"))
	h1 := sha256.Sum256([]byte("h1"))
	h2 := sha256.Sum256([]byte("h2"))

	// Establish initial valid ServingState at size 100
	if _, err := pub.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, &log.Checkpoint{
		Size: 100, Hash: h1[:], // empty Origin inherits pub.InputOrigin()
	}); err != nil {
		t.Fatalf("initial PublishKeyBatch failed: %v", err)
	}

	for name, fn := range map[string]func() error{
		"nil_input_cp": func() error {
			_, err := pub.PublishKeyBatch(ctx, nil, nil)
			return err
		},
		"mismatched_configured_origin": func() error {
			_, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "other.example/log", Size: 110, Hash: h2[:]})
			return err
		},
		"from_exceeds_size": func() error {
			p := NewOutputPublisher(mpt.NewMem(), outLog)
			p.SetFrom(50)
			_, err := p.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 10, Hash: h1[:]})
			return err
		},
		"invalid_origin_syntax": func() error {
			p := NewOutputPublisher(mpt.NewMem(), outLog)
			_, err := p.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: " leading-space", Size: 10, Hash: h1[:]})
			return err
		},
		"invalid_hash_len": func() error {
			_, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 110, Hash: []byte{1, 2, 3}})
			return err
		},
		"size_zero_non_empty_hash": func() error {
			p := NewOutputPublisher(mpt.NewMem(), outLog)
			_, err := p.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 0, Hash: h1[:]})
			return err
		},
		"size_equals_from_non_empty_keys": func() error {
			p := NewOutputPublisher(mpt.NewMem(), outLog)
			p.SetFrom(50)
			_, err := p.PublishKeyBatch(ctx, map[string][32]byte{"com.example.a": val1}, &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: h1[:]})
			return err
		},
		"size_regressed": func() error {
			_, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 90, Hash: h2[:]})
			return err
		},
		"same_size_split_view_hash": func() error {
			_, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 100, Hash: h2[:]})
			return err
		},
		"from_changed_across_entries": func() error {
			pub.SetFrom(60)
			defer pub.SetFrom(50)
			_, err := pub.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 110, Hash: h2[:]})
			return err
		},
		"non_tip_output_log_index": func() error {
			badIdx := uint64(99)
			p := NewOutputPublisher(mpt.NewMem(), &fakeOutputLog{origin: "example.com/outputlog", forceIdx: &badIdx})
			_, err := p.PublishKeyBatch(ctx, nil, &log.Checkpoint{Origin: "example.com/inputlog", Size: 10, Hash: h1[:]})
			return err
		},
	} {
		if err := fn(); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
