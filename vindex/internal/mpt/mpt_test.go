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

package mpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	torchmpt "filippo.io/torchwood/mpt"
)

// skipIfRaceDarwin skips disk-backed MPT tests under the race detector on macOS.
// Each torchwood/mpt disk open reserves a 16 TiB virtual address space span via mmap,
// which on macOS collides with ThreadSanitizer's fixed [0x00c000000000, 0x00e000000000)
// Go heap arena and crashes the runtime with "too many address space collisions for -race mode"
// (matching upstream filippo.io/torchwood/mpt/internal/pmem/pmem_test.go).
// Disk-backed MPT tests still run on macOS without -race and on Linux with -race.
func skipIfRaceDarwin(t *testing.T) {
	t.Helper()
	if raceEnabled && runtime.GOOS == "darwin" {
		t.Skip("skipping disk-backed torchwood/mpt test under the race detector on macOS")
	}
}

func verifyAllKeys(t *testing.T, mgr *Manager, root [sha256.Size]byte, mutations map[string][sha256.Size]byte, missingKey []byte) {
	t.Helper()
	for k, wantVal := range mutations {
		proof, gotVal, exists, err := mgr.ProveKey([]byte(k))
		if err != nil || !exists || gotVal != wantVal {
			t.Fatalf("ProveKey(%q): exists=%v val=%x err=%v, want %x", k, exists, gotVal, err, wantVal)
		}
		if err := VerifyKey(root, []byte(k), gotVal, true, proof); err != nil {
			t.Fatalf("VerifyKey(%q) inclusion failed: %v", k, err)
		}
	}
	if len(missingKey) > 0 {
		proof, val, exists, err := mgr.ProveKey(missingKey)
		if err != nil || exists {
			t.Fatalf("ProveKey(%q): exists=%v err=%v, want absent", missingKey, exists, err)
		}
		if err := VerifyKey(root, missingKey, val, false, proof); err != nil {
			t.Fatalf("VerifyKey(%q) non-inclusion failed: %v", missingKey, err)
		}
	}
}

func provePrefixHelper(mgr *Manager, prefix []byte, maxKeys int) ([]byte, []PrefixKeyVal, error) {
	mgr.RLock()
	defer mgr.RUnlock()
	return mgr.ProvePrefixLocked(prefix, maxKeys)
}

func TestMPT_EmptyTree(t *testing.T) {
	mgr := NewMem()
	emptyRoot := sha256.Sum256(nil)
	if mgr.Root() != emptyRoot {
		t.Fatalf("Empty tree root = %x, want %x", mgr.Root(), emptyRoot)
	}
	verifyAllKeys(t, mgr, emptyRoot, nil, []byte("com.example.nonexistent"))

	proof, matches, err := provePrefixHelper(mgr, []byte("com.example."), 0)
	if err != nil || len(matches) != 0 || len(proof) != 0 {
		t.Fatalf("ProvePrefixLocked on empty tree: len(matches)=%d len(proof)=%d err=%v", len(matches), len(proof), err)
	}
	if err := VerifyPrefix(emptyRoot, []byte("com.example."), matches, proof); err != nil {
		t.Fatalf("VerifyPrefix on empty tree failed: %v", err)
	}
}

func TestKeyCompareAndCanonicalBounds(t *testing.T) {
	keys := []string{
		"!",
		"com.example.",
		"com.example.*.",
		"com.example.a.",
		"com.example.aa.",
		"com.example.b.",
		"com.googleapis.",
		"~",
	}
	for i := range keys {
		for j := range keys {
			got := torchmpt.Key(keys[i]).Compare(torchmpt.Key(keys[j]))
			want := bytes.Compare([]byte(keys[i]), []byte(keys[j]))
			if got != want {
				t.Fatalf("Key(%q).Compare(%q) = %d, want %d", keys[i], keys[j], got, want)
			}
		}
	}

	if err := ValidateCanonicalKey([]byte("!")); err != nil {
		t.Fatalf("ValidateCanonicalKey(1 byte) failed: %v", err)
	}
	maxKey := make([]byte, MaxKeyLen)
	for i := range maxKey {
		maxKey[i] = byte(0x21 + (i % (0x7E - 0x21 + 1)))
	}
	if err := ValidateCanonicalKey(maxKey); err != nil {
		t.Fatalf("ValidateCanonicalKey(1024 bytes) failed: %v", err)
	}

	for _, bad := range [][]byte{
		nil,
		{},
		bytes.Repeat([]byte("a"), MaxKeyLen+1),
		[]byte("bad\x00key"),
		[]byte("bad key"),
		[]byte("bad\x7fkey"),
		[]byte("bad\x80key"),
	} {
		if err := ValidateCanonicalKey(bad); err == nil {
			t.Fatalf("ValidateCanonicalKey(len=%d) succeeded, want error", len(bad))
		}
	}
}

func TestMPT_PredictMatchesCommit(t *testing.T) {
	mgr := NewMem()

	mutations := make(map[string][sha256.Size]byte, 500)
	for i := range 500 {
		k := fmt.Sprintf("com.example.key_%d.", i)
		mutations[k] = sha256.Sum256([]byte(fmt.Sprintf("val_%d", i)))
	}

	predictedRoot, err := mgr.PredictKeys(mutations)
	if err != nil {
		t.Fatalf("PredictKeys failed: %v", err)
	}
	actualRoot, err := mgr.CommitKeysWithVersion(mutations, 500)
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	if actualRoot != predictedRoot || mgr.Root() != actualRoot {
		t.Fatalf("root mismatch: predicted=%x actual=%x mgr=%x", predictedRoot, actualRoot, mgr.Root())
	}
	verifyAllKeys(t, mgr, actualRoot, mutations, []byte("com.example.absent."))
}

func setupBenchMPT(b *testing.B, numKeys int) (*Manager, [][]byte) {
	b.Helper()
	mptDir := b.TempDir()
	if raceEnabled && runtime.GOOS == "darwin" {
		mptDir = ":memory:"
	}
	mgr, err := Open(mptDir)
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	b.Cleanup(func() { _ = mgr.Close() })

	keys := make([][]byte, numKeys)
	initialMutations := make(map[string][sha256.Size]byte, numKeys)
	for i := range numKeys {
		k := fmt.Sprintf("com.example.bench_%d.", i)
		keys[i] = []byte(k)
		initialMutations[k] = sha256.Sum256([]byte(fmt.Sprintf("bench_val_%d", i)))
	}
	if _, err := mgr.CommitKeysWithVersion(initialMutations, int64(numKeys)); err != nil {
		b.Fatalf("initial CommitKeysWithVersion failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		b.Fatalf("initial Persist failed: %v", err)
	}
	return mgr, keys
}

func BenchmarkMPT_Prove_NoSync(b *testing.B) {
	const numKeys = 2000
	mgr, keys := setupBenchMPT(b, numKeys)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := keys[i%numKeys]
			mgr.RLock()
			_, _, _, err := mgr.ProveKeyLocked(k)
			mgr.RUnlock()
			if err != nil {
				b.Errorf("ProveKeyLocked failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkMPT_ReadContentionDuringSync(b *testing.B) {
	const numKeys = 2000
	mgr, keys := setupBenchMPT(b, numKeys)
	keyStrs := make([]string, numKeys)
	for i, k := range keys {
		keyStrs[i] = string(k)
	}

	stopCh := make(chan struct{})
	var bgWG sync.WaitGroup
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		counter := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				counter++
				muts := make(map[string][sha256.Size]byte, 10)
				for j := range 10 {
					k := keyStrs[(counter*10+j)%numKeys]
					muts[k] = sha256.Sum256([]byte(fmt.Sprintf("val_update_%d_%d", counter, j)))
				}
				_, _ = mgr.CommitKeysWithVersion(muts, int64(counter))
				_ = mgr.Persist()
			}
		}
	}()
	b.Cleanup(func() {
		close(stopCh)
		bgWG.Wait()
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			k := keys[i%numKeys]
			mgr.RLock()
			_, _, _, err := mgr.ProveKeyLocked(k)
			mgr.RUnlock()
			if err != nil {
				b.Errorf("ProveKeyLocked failed: %v", err)
			}
			i++
		}
	})
}

func TestMPT_SetKeyBatchAndSnap(t *testing.T) {
	mgr := NewMem()

	mutations := make(map[string][sha256.Size]byte, 200)
	for i := range 200 {
		k := fmt.Sprintf("com.example.genesis_%d.", i)
		mutations[k] = sha256.Sum256([]byte(fmt.Sprintf("genesis_val_%d", i)))
	}

	predictedRoot, err := mgr.PredictKeys(mutations)
	if err != nil {
		t.Fatalf("PredictKeys failed: %v", err)
	}
	if err := mgr.SetKeyBatch(mutations); err != nil {
		t.Fatalf("SetKeyBatch failed: %v", err)
	}
	snappedRoot, err := mgr.Snap(200)
	if err != nil {
		t.Fatalf("Snap failed: %v", err)
	}
	if snappedRoot != predictedRoot {
		t.Fatalf("snappedRoot %x != predictedRoot %x", snappedRoot, predictedRoot)
	}
	if mgr.PersistedSize() != 0 {
		t.Fatalf("PersistedSize before Persist() = %d, want 0", mgr.PersistedSize())
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}
	if mgr.PersistedSize() != 200 {
		t.Fatalf("PersistedSize after Persist() = %d, want 200", mgr.PersistedSize())
	}
}

func TestMPT_DirtyCrashPreservesNonExactAcrossMultipleRestarts(t *testing.T) {
	skipIfRaceDarwin(t)
	dir := t.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !mgr.IsExact() {
		t.Fatal("freshly opened MPT should have IsExact() == true")
	}

	v0 := sha256.Sum256([]byte("clean_val"))
	if _, err := mgr.CommitKeysWithVersion(map[string][32]byte{"com.example.clean.": v0}, 10); err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist failed: %v", err)
	}
	if !mgr.IsExact() {
		t.Fatal("after CommitKeysWithVersion + Persist, IsExact() should be true")
	}

	v := sha256.Sum256([]byte("dirty_val"))
	if err := mgr.SetKeyBatch(map[string][32]byte{"com.example.dirty.": v}); err != nil {
		t.Fatalf("SetKeyBatch failed: %v", err)
	}
	if mgr.IsExact() {
		t.Fatal("after SetKeyBatch without Snap, IsExact() should be false")
	}
	// Empty PredictBatch and ProveKey on dirty tree must fail with ErrModifiedTree!
	if _, err := mgr.PredictKeys(nil); !errors.Is(err, torchmpt.ErrModifiedTree) {
		t.Fatalf("PredictKeys(nil) on dirty tree = %v, want ErrModifiedTree", err)
	}
	if _, _, _, err := mgr.ProveKey([]byte("com.example.clean.")); !errors.Is(err, torchmpt.ErrModifiedTree) {
		t.Fatalf("ProveKey on dirty tree = %v, want ErrModifiedTree", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen 1 (without replay) -> Close -> Reopen 2: IsExact() must stay false!
	mgr2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen 1 failed: %v", err)
	}
	if mgr2.IsExact() {
		_ = mgr2.Close()
		t.Fatal("reopen 1 must preserve IsExact() == false")
	}
	if _, err := mgr2.PredictKeys(nil); !errors.Is(err, torchmpt.ErrModifiedTree) {
		_ = mgr2.Close()
		t.Fatalf("PredictKeys(nil) on unrecovered reopen = %v, want ErrModifiedTree", err)
	}
	if filepath.Base(mgr2.syncCtl.files[0].f.Name()) != "mpt.disk" {
		_ = mgr2.Close()
		t.Fatalf("syncCtl.files[0] = %q, want mpt.disk synced first", filepath.Base(mgr2.syncCtl.files[0].f.Name()))
	}
	if err := mgr2.Close(); err != nil {
		t.Fatalf("Close 2 failed: %v", err)
	}

	mgr3, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen 2 failed: %v", err)
	}
	if mgr3.IsExact() || mgr3.PersistedSize() != 10 {
		_ = mgr3.Close()
		t.Fatalf("reopen 2: exact=%v size=%d, want false and 10", mgr3.IsExact(), mgr3.PersistedSize())
	}
	// CommitKeysWithVersion WITHOUT Persist() followed by Close() must NOT promote exact=true on disk!
	if _, err := mgr3.CommitKeysWithVersion(map[string][32]byte{"com.example.unpersisted.": v}, 99); err != nil {
		_ = mgr3.Close()
		t.Fatalf("CommitKeysWithVersion(99) failed: %v", err)
	}
	if err := mgr3.Close(); err != nil {
		t.Fatalf("Close 3 failed: %v", err)
	}

	mgr4, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen 3 failed: %v", err)
	}
	defer func() { _ = mgr4.Close() }()
	if mgr4.IsExact() {
		t.Fatal("un-Persisted CommitKeysWithVersion followed by Close must reopen with IsExact() == false")
	}
}

func TestMPT_DiskPersistence_ReopenAndStubRecovery(t *testing.T) {
	skipIfRaceDarwin(t)
	// 1. 0-byte stub left from interrupted initial Open recovers cleanly instead of EEXIST
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "mpt.tree1"), nil, 0o644); err != nil {
		t.Fatalf("WriteFile stub failed: %v", err)
	}
	stubMgr, err := Open(stubDir)
	if err != nil {
		t.Fatalf("Open(0-byte stub dir) failed: %v", err)
	}
	_ = stubMgr.Close()

	// 2. Partial / 0-byte truncated companion files are rejected as corrupt
	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, "mpt.tree1"), []byte("garbage_data_too_short"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(corruptDir); err == nil {
		t.Fatal("expected error opening partial/corrupted mpt.tree1, got nil")
	}
	truncCompanionDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(truncCompanionDir, "mpt.tree1"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(truncCompanionDir, "mpt.tree2"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(truncCompanionDir, "mpt.disk"), []byte("non_empty_leaf_data"), 0o644)
	if _, err := Open(truncCompanionDir); err == nil {
		t.Fatal("expected error when mpt.tree1/tree2 are truncated to 0 bytes alongside non-empty mpt.disk")
	}

	// 3. Normal CommitBatchAndPersist + Reopen
	dir := t.TempDir()
	mgr, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	mutations := make(map[string][sha256.Size]byte, 50)
	for i := range 50 {
		k := fmt.Sprintf("com.example.persist_%d.", i)
		mutations[k] = sha256.Sum256([]byte(fmt.Sprintf("persist_val_%d", i)))
	}
	batch, err := PrepareBatch(mutations)
	if err != nil {
		t.Fatalf("PrepareBatch failed: %v", err)
	}
	var callbackCalled bool
	actualRoot, err := mgr.CommitBatchAndPersist(batch, 50, func(r [sha256.Size]byte) {
		callbackCalled = true
	})
	if err != nil || !callbackCalled {
		t.Fatalf("CommitBatchAndPersist err=%v callbackCalled=%v", err, callbackCalled)
	}
	if mgr.PersistedSize() != 50 {
		t.Fatalf("PersistedSize = %d, want 50", mgr.PersistedSize())
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	mgr2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() { _ = mgr2.Close() }()

	if mgr2.Root() != actualRoot || mgr2.PersistedSize() != 50 || !mgr2.IsExact() {
		t.Fatalf("Reopened state mismatch: root=%x size=%d exact=%v", mgr2.Root(), mgr2.PersistedSize(), mgr2.IsExact())
	}
	verifyAllKeys(t, mgr2, actualRoot, mutations, []byte("com.example.absent."))
}

func TestMPT_VariableLengthKeysAndPrefixEdgeCases(t *testing.T) {
	mgr := NewMem()

	maxPrefix1024 := strings.Repeat("p", MaxKeyLen)
	sibling1023 := maxPrefix1024[:MaxKeyLen-1]
	maxTilde1024 := strings.Repeat("~", MaxKeyLen)

	mutations := map[string][sha256.Size]byte{
		"!":                sha256.Sum256([]byte("min_ascii")),
		"com.google.":      sha256.Sum256([]byte("val_apex")),
		"com.google.*.":    sha256.Sum256([]byte("val_wildcard")),
		"com.google.docs.": sha256.Sum256([]byte("val_docs")),
		"com.google.mail.": sha256.Sum256([]byte("val_mail")),
		"com.googleapis.":  sha256.Sum256([]byte("val_apis")),
		sibling1023:        sha256.Sum256([]byte("val_1023")),
		maxPrefix1024:      sha256.Sum256([]byte("val_1024")),
		"~":                sha256.Sum256([]byte("tilde_1")),
		maxTilde1024:       sha256.Sum256([]byte("max_ascii")),
	}

	predictedRoot, err := mgr.PredictKeys(mutations)
	if err != nil {
		t.Fatalf("PredictKeys failed: %v", err)
	}
	actualRoot, err := mgr.CommitKeysWithVersion(mutations, 1)
	if err != nil || actualRoot != predictedRoot {
		t.Fatalf("CommitKeysWithVersion root=%x want=%x err=%v", actualRoot, predictedRoot, err)
	}
	verifyAllKeys(t, mgr, actualRoot, mutations, []byte("com.example.absent."))

	for _, tc := range []struct {
		name      string
		prefix    string
		wantCount int
	}{
		{name: "multi_key_domain_prefix", prefix: "com.google.", wantCount: 4},
		{name: "exact_leaf_zero_descendants", prefix: "com.google.docs.", wantCount: 1},
		{name: "extension_beyond_leaf_no_descendants", prefix: "com.google.docs.sub.", wantCount: 0},
		{name: "max_1024_byte_prefix_present", prefix: maxPrefix1024, wantCount: 1},
		{name: "1023_byte_prefix_includes_1024_child", prefix: sibling1023, wantCount: 2},
		{name: "min_ascii_0x21", prefix: "!", wantCount: 1},
		{name: "below_min_second_byte", prefix: "!!", wantCount: 0},
		{name: "tilde_prefix_includes_max_1024", prefix: "~", wantCount: 2},
		{name: "absent_max_1024_prefix", prefix: strings.Repeat("z", MaxKeyLen), wantCount: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pBytes := []byte(tc.prefix)
			proof, matches, err := provePrefixHelper(mgr, pBytes, 0)
			if err != nil {
				t.Fatalf("ProvePrefixLocked(%q) failed: %v", tc.name, err)
			}
			if len(matches) != tc.wantCount {
				t.Fatalf("len(matches) = %d, want %d", len(matches), tc.wantCount)
			}
			if err := VerifyPrefix(actualRoot, pBytes, matches, proof); err != nil {
				t.Fatalf("VerifyPrefix(%q) failed: %v", tc.name, err)
			}
		})
	}

	// Prefix matching the entire non-empty MPT produces an empty proof (len == 0)
	mgrSinglePrefix := NewMem()
	allUnderCom := map[string][32]byte{
		"com.a": sha256.Sum256([]byte("a")),
		"com.b": sha256.Sum256([]byte("b")),
	}
	rootAllCom, _ := mgrSinglePrefix.CommitKeysWithVersion(allUnderCom, 1)
	fullProof, fullMatches, err := provePrefixHelper(mgrSinglePrefix, []byte("com."), 0)
	if err != nil || len(fullProof) != 0 || len(fullMatches) != 2 {
		t.Fatalf("whole-tree prefix: len(proof)=%d len(matches)=%d err=%v", len(fullProof), len(fullMatches), err)
	}
	if err := VerifyPrefix(rootAllCom, []byte("com."), fullMatches, fullProof); err != nil {
		t.Fatalf("VerifyPrefix(whole-tree) failed: %v", err)
	}
	// Wider-ancestor substitution attack: claiming whole-tree empty proof for narrower "com.a" while omitting "com.b" or including "com.b"
	if err := VerifyPrefix(rootAllCom, []byte("com.a"), fullMatches, fullProof); err == nil {
		t.Fatal("expected VerifyPrefix to reject key outside prefix (wider-ancestor substitution)")
	}
	if err := VerifyPrefix(rootAllCom, []byte("com.a"), fullMatches[:1], fullProof); err == nil {
		t.Fatal("expected VerifyPrefix to reject omitted sibling key")
	}

	// maxKeys limit enforcement
	if _, _, err := provePrefixHelper(mgr, []byte("com.google."), 3); !errors.Is(err, ErrPrefixTooManyKeys) {
		t.Fatalf("ProvePrefixLocked(maxKeys=3) err = %v, want ErrPrefixTooManyKeys", err)
	}
}

func BenchmarkMPT_ProvePrefix(b *testing.B) {
	mgr := NewMem()
	mutations := make(map[string][sha256.Size]byte, 2000)
	for i := range 2000 {
		var k string
		if i < 50 {
			k = fmt.Sprintf("com.google.sub%04d.", i)
		} else {
			k = fmt.Sprintf("org.other%04d.sub.", i)
		}
		mutations[k] = sha256.Sum256([]byte(k))
	}
	root, err := mgr.CommitKeysWithVersion(mutations, 1)
	if err != nil {
		b.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	prefix := []byte("com.google.")

	b.ReportAllocs()
	for b.Loop() {
		proof, matches, err := provePrefixHelper(mgr, prefix, 1000)
		if err != nil {
			b.Fatalf("ProvePrefixLocked failed: %v", err)
		}
		if err := VerifyPrefix(root, prefix, matches, proof); err != nil {
			b.Fatalf("VerifyPrefix failed: %v", err)
		}
	}
}

func TestMPT_ConcurrentPersistAndReaders_Race(t *testing.T) {
	mptDir := t.TempDir()
	if raceEnabled && runtime.GOOS == "darwin" {
		mptDir = ":memory:"
	}
	mgr, err := Open(mptDir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	initial := make(map[string][sha256.Size]byte, 64)
	for i := range 64 {
		k := fmt.Sprintf("com.example.k%03d.", i)
		initial[k] = sha256.Sum256([]byte(k))
	}
	if _, err := mgr.CommitKeysWithVersion(initial, 100); err != nil {
		t.Fatalf("initial CommitKeysWithVersion failed: %v", err)
	}
	if err := mgr.Persist(); err != nil {
		t.Fatalf("initial Persist failed: %v", err)
	}

	const rounds = 25
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	reportErr := func(e error) {
		select {
		case errCh <- e:
		default:
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := 1; r <= rounds; r++ {
			batch, err := PrepareBatch(map[string][sha256.Size]byte{
				fmt.Sprintf("com.example.dyn%03d.", r): sha256.Sum256([]byte(fmt.Sprintf("v-%d", r))),
			})
			if err != nil {
				reportErr(err)
				return
			}
			if _, err := mgr.CommitBatchAndPersist(batch, int64(100+r), nil); err != nil {
				reportErr(fmt.Errorf("CommitBatchAndPersist(%d): %w", r, err))
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range rounds * 4 {
			k := []byte(fmt.Sprintf("com.example.k%03d.", r%64))
			if _, _, exists, err := mgr.ProveKey(k); err != nil || !exists {
				reportErr(fmt.Errorf("ProveKey(%q): exists=%v err=%w", k, exists, err))
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		prefix := []byte("com.example.")
		for range rounds * 2 {
			if _, matches, err := provePrefixHelper(mgr, prefix, 0); err != nil || len(matches) < 64 {
				reportErr(fmt.Errorf("ProvePrefixLocked: len=%d err=%w", len(matches), err))
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		cand := map[string][sha256.Size]byte{
			"org.candidate.test.": sha256.Sum256([]byte("cand")),
		}
		for range rounds * 2 {
			if _, err := mgr.PredictKeys(cand); err != nil {
				reportErr(fmt.Errorf("PredictKeys: %w", err))
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatalf("concurrent MPT race/error: %v", e)
	}
	if got := mgr.PersistedSize(); got != uint64(100+rounds) {
		t.Fatalf("PersistedSize() = %d, want %d", got, 100+rounds)
	}
}

func testMPTLeafHash(key, val []byte) [sha256.Size]byte {
	var buf []byte
	buf = append(buf, 0x00)
	buf = binary.AppendUvarint(buf, uint64(len(key)))
	buf = append(buf, key...)
	buf = binary.AppendUvarint(buf, uint64(len(val)))
	buf = append(buf, val...)
	return sha256.Sum256(buf)
}

func testMPTInnerHash(bitPos uint64, left, right [sha256.Size]byte) [sha256.Size]byte {
	var buf []byte
	buf = append(buf, 0x01)
	buf = binary.AppendUvarint(buf, bitPos)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

func TestVerify_AdversarialWireBounds(t *testing.T) {
	val32 := sha256.Sum256([]byte("value-root"))
	sibHash := sha256.Sum256([]byte("sibling-node"))

	t.Run("reject_split_bit_8193_and_non_decreasing_split_bits_and_trailing_bytes", func(t *testing.T) {
		key := []byte("com.example.key")
		leafH := testMPTLeafHash(key, val32[:])
		forgedRoot := testMPTInnerHash(8193, sibHash, leafH)
		var proof8193 []byte
		proof8193 = binary.AppendUvarint(proof8193, 8193)
		proof8193 = append(proof8193, sibHash[:]...)
		if err := VerifyKey(forgedRoot, key, val32, true, proof8193); err == nil {
			t.Fatal("expected VerifyKey to reject split bit 8193")
		}

		// Non-decreasing split bits (10 followed by 10)
		var nonDecProof []byte
		nonDecProof = binary.AppendUvarint(nonDecProof, 10)
		nonDecProof = append(nonDecProof, sibHash[:]...)
		nonDecProof = binary.AppendUvarint(nonDecProof, 10)
		nonDecProof = append(nonDecProof, sibHash[:]...)
		if err := VerifyKey(forgedRoot, key, val32, true, nonDecProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(non-decreasing split bits) = %v, want ErrInvalidProof", err)
		}

		// Trailing garbage bytes after valid step
		var trailingProof []byte
		trailingProof = binary.AppendUvarint(trailingProof, 10)
		trailingProof = append(trailingProof, sibHash[:]...)
		trailingProof = append(trailingProof, 0x05, 0x01)
		if err := VerifyKey(forgedRoot, key, val32, true, trailingProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(trailing bytes) = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("reject_narrower_subtree_omission_and_unsorted_or_duplicate_matches", func(t *testing.T) {
		// Prefix "a" (8 bits), step b_1 = 8 (>= 8*len(prefix)) attempts to omit sibling under "a"
		var narrowProof []byte
		narrowProof = binary.AppendUvarint(narrowProof, 8)
		narrowProof = append(narrowProof, sibHash[:]...)
		matches := []PrefixKeyVal{{Key: "ab", ValueRoot: val32}}
		leafH := testMPTLeafHash([]byte("ab"), val32[:])
		root := testMPTInnerHash(8, leafH, sibHash)
		if err := VerifyPrefix(root, []byte("a"), matches, narrowProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(b_1 >= 8*len(prefix)) = %v, want ErrInvalidProof", err)
		}

		// Duplicate and unsorted matches must be rejected without panicking in TreeHash
		dupMatches := []PrefixKeyVal{{Key: "ab", ValueRoot: val32}, {Key: "ab", ValueRoot: val32}}
		if err := VerifyPrefix(root, []byte("a"), dupMatches, nil); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(duplicate matches) = %v, want ErrInvalidProof", err)
		}
		unsortedMatches := []PrefixKeyVal{{Key: "ac", ValueRoot: val32}, {Key: "ab", ValueRoot: val32}}
		if err := VerifyPrefix(root, []byte("a"), unsortedMatches, nil); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(unsorted matches) = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("reject_non_canonical_path_key_and_invalid_path_val_length", func(t *testing.T) {
		for _, badPK := range [][]byte{{}, []byte("bad key"), bytes.Repeat([]byte("a"), 1025)} {
			forgedRoot := testMPTLeafHash(badPK, val32[:])
			var proof []byte
			proof = binary.AppendUvarint(proof, uint64(len(badPK)))
			proof = append(proof, badPK...)
			proof = binary.AppendUvarint(proof, uint64(len(val32)))
			proof = append(proof, val32[:]...)

			if err := VerifyKey(forgedRoot, []byte("com.example.missing"), [32]byte{}, false, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyKey(badPK len=%d) err = %v, want ErrInvalidProof", len(badPK), err)
			}
			if err := VerifyPrefix(forgedRoot, []byte("com.example.none."), nil, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
				t.Fatalf("VerifyPrefix(badPK len=%d) err = %v, want ErrInvalidProof", len(badPK), err)
			}
		}

		goodPK := []byte("com.example.present")
		shortVal := make([]byte, 16)
		forgedRoot := testMPTLeafHash(goodPK, shortVal)
		var proof []byte
		proof = binary.AppendUvarint(proof, uint64(len(goodPK)))
		proof = append(proof, goodPK...)
		proof = binary.AppendUvarint(proof, uint64(len(shortVal)))
		proof = append(proof, shortVal...)

		if err := VerifyKey(forgedRoot, []byte("com.example.absent"), [32]byte{}, false, proof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(len(path_val)=16) err = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("reject_overlong_and_overflow_uvarints_and_non_empty_proof_on_empty_mpt", func(t *testing.T) {
		key := []byte("a")
		leafH := testMPTLeafHash(key, val32[:])
		root := testMPTInnerHash(0, leafH, sibHash)

		overlongStepProof := append([]byte{0x80, 0x00}, sibHash[:]...)
		if err := VerifyKey(root, key, val32, true, overlongStepProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(overlong step uvarint) err = %v, want ErrInvalidProof", err)
		}

		// 11-byte overflow uvarint
		overflowProof := append(bytes.Repeat([]byte{0x80}, 10), 0x02)
		overflowProof = append(overflowProof, sibHash[:]...)
		if err := VerifyKey(root, key, val32, true, overflowProof); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(11-byte overflow uvarint) err = %v, want ErrInvalidProof", err)
		}

		emptyRoot := sha256.Sum256(nil)
		if err := VerifyKey(emptyRoot, []byte("b"), [32]byte{}, false, []byte{0x00}); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyKey(empty MPT with non-empty proof) err = %v, want ErrInvalidProof", err)
		}
		if err := VerifyPrefix(emptyRoot, []byte("b"), nil, []byte{0x00}); !errors.Is(err, torchmpt.ErrInvalidProof) {
			t.Fatalf("VerifyPrefix(empty MPT with non-empty proof) err = %v, want ErrInvalidProof", err)
		}
	})
}
