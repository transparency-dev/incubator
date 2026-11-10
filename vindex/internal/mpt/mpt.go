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

// Package mpt provides a Sparse Merkle Patricia Trie manager and proof verifier
// over variable-length canonical keys without storage or Output Log dependencies.
package mpt

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	torchmpt "filippo.io/torchwood/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// MaxKeyLen is the maximum length in bytes of a canonical key stored in the MPT (1024 bytes).
const MaxKeyLen = torchmpt.MaxKeyLen

var emptyMPTHash = sha256.Sum256(nil)

// ErrPrefixTooManyKeys is returned when a prefix scan exceeds the configured maximum key cardinality.
var ErrPrefixTooManyKeys = errors.New("prefix scan exceeded maximum allowed keys")

// PrefixKeyVal represents a canonical key and its 32-byte value log root yielded by a prefix scan.
type PrefixKeyVal = wire.KeyValueRoot

// ValidateCanonicalKey checks that key is between 1 and 1024 printable ASCII bytes (0x21..0x7E),
// containing no NUL (0x00) bytes or ASCII whitespace.
func ValidateCanonicalKey(key []byte) error {
	return wire.ValidateCanonicalKey(key)
}

// Batch holds pre-validated, canonically sorted key-value mutations ready for prediction and commitment.
type Batch struct {
	changes []torchmpt.KeyVal
}

// PrepareBatch validates canonical keys, packs 32-byte value roots contiguously, and sorts keys once.
func PrepareBatch(mutations map[string][sha256.Size]byte) (Batch, error) {
	if len(mutations) == 0 {
		return Batch{}, nil
	}
	vals := make([]byte, len(mutations)*sha256.Size)
	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	i := 0
	for k, v := range mutations {
		if err := ValidateCanonicalKey([]byte(k)); err != nil {
			return Batch{}, err
		}
		vb := vals[i*sha256.Size : (i+1)*sha256.Size : (i+1)*sha256.Size]
		copy(vb, v[:])
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(vb),
		})
		i++
	}
	slices.SortFunc(changes, torchmpt.KeyVal.CompareKey)
	return Batch{changes: changes}, nil
}

type syncCtl struct {
	deferSync bool
	files     []*deferredSyncFile
}

func (c *syncCtl) syncPending() error {
	if c == nil {
		return nil
	}
	for _, df := range c.files {
		if df.pendingSync || df.dirty {
			if err := df.f.Sync(); err != nil {
				return err
			}
			df.pendingSync = false
			df.dirty = false
		}
	}
	return nil
}

type deferredSyncFile struct {
	f           *os.File
	ctl         *syncCtl
	size        int64
	pendingSync bool
	dirty       bool
}

func (d *deferredSyncFile) ReadAt(b []byte, off int64) (int, error) {
	return d.f.ReadAt(b, off)
}

func (d *deferredSyncFile) WriteAt(b []byte, off int64) (int, error) {
	if d.ctl != nil && (d.pendingSync || off < d.size) {
		for _, peer := range d.ctl.files {
			if peer.pendingSync {
				if err := peer.f.Sync(); err != nil {
					return 0, err
				}
				peer.pendingSync = false
				peer.dirty = false
			}
		}
	}
	d.dirty = true
	n, err := d.f.WriteAt(b, off)
	if end := off + int64(n); end > d.size {
		d.size = end
	}
	return n, err
}

func (d *deferredSyncFile) Sync() error {
	if d.ctl != nil && d.ctl.deferSync {
		d.pendingSync = true
		return nil
	}
	if err := d.f.Sync(); err != nil {
		return err
	}
	d.pendingSync = false
	d.dirty = false
	return nil
}

func (d *deferredSyncFile) Close() error {
	return d.f.Close()
}

var _ torchmpt.File = (*deferredSyncFile)(nil)

// Manager manages a Merkle Patricia Trie with thread-safe read access and lock-free root prediction.
type Manager struct {
	writeMu     sync.Mutex   // Serializes Commit, Persist, and Close operations
	treeMu      sync.RWMutex // Protects in-memory trie operations (Prove, Predict, Snap, Sync, root swaps)
	tree        torchmpt.Tree
	syncCtl     *syncCtl
	currentRoot [sha256.Size]byte
	durableSize atomic.Uint64
	exact       atomic.Bool
}

// Open opens an existing MPT in the specified directory or creates a new one.
// If dir is empty or ":memory:", an in-memory tree is used.
func Open(dir string) (*Manager, error) {
	var tree torchmpt.Tree
	var ctl *syncCtl
	isNew := false
	if dir == "" || dir == ":memory:" {
		tree = torchmpt.NewMemTree()
		isNew = true
	} else {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create mpt dir: %w", err)
		}
		paths := [3]string{
			filepath.Join(dir, "mpt.tree1"),
			filepath.Join(dir, "mpt.tree2"),
			filepath.Join(dir, "mpt.disk"),
		}
		var sizes [3]int64
		var existsCount, nonEmptyCount int
		for i, p := range paths {
			st, err := os.Stat(p)
			if err == nil {
				existsCount++
				sizes[i] = st.Size()
				if sizes[i] > 0 {
					nonEmptyCount++
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("stat %q failed: %w", p, err)
			}
		}
		if nonEmptyCount > 0 && nonEmptyCount < len(paths) {
			return nil, fmt.Errorf("corrupt mpt directory %q: partial non-empty file set (%d/3 non-empty)", dir, nonEmptyCount)
		}

		flag := os.O_RDWR
		if nonEmptyCount == 0 {
			flag = os.O_RDWR | os.O_CREATE
			isNew = true
		}

		var files [3]*os.File
		closeOpened := func() {
			for _, f := range files {
				if f != nil {
					_ = f.Close()
				}
			}
		}
		for i, p := range paths {
			f, err := os.OpenFile(p, flag, 0o666)
			if err != nil {
				closeOpened()
				return nil, fmt.Errorf("open %q failed: %w", p, err)
			}
			files[i] = f
		}
		if isNew {
			if dirFD, err := os.Open(dir); err == nil {
				_ = dirFD.Sync()
				_ = dirFD.Close()
			}
		}

		ctl = &syncCtl{}
		df1 := &deferredSyncFile{f: files[0], ctl: ctl, size: sizes[0]}
		df2 := &deferredSyncFile{f: files[1], ctl: ctl, size: sizes[1]}
		df3 := &deferredSyncFile{f: files[2], ctl: ctl, size: sizes[2]}
		ctl.files = []*deferredSyncFile{df3, df1, df2}

		var openErr error
		tree, openErr = torchmpt.New(df1, df2, df3)
		if openErr != nil {
			closeOpened()
			return nil, fmt.Errorf("torchmpt.New failed: %w", openErr)
		}
	}

	initVer, initExact := tree.Version()
	var currentRoot [sha256.Size]byte
	if isNew {
		snap, err := tree.Snap(0)
		if err != nil {
			_ = tree.Close()
			return nil, fmt.Errorf("initial Snap failed: %w", err)
		}
		if err := tree.Sync(); err != nil {
			_ = tree.Close()
			return nil, fmt.Errorf("initial Sync failed: %w", err)
		}
		if err := ctl.syncPending(); err != nil {
			_ = tree.Close()
			return nil, fmt.Errorf("initial fsync failed: %w", err)
		}
		currentRoot = [sha256.Size]byte(snap.Hash)
		initExact = true
	} else if initExact {
		snap, err := tree.Snap(-1)
		if err != nil {
			_ = tree.Close()
			return nil, fmt.Errorf("Snap(-1) failed: %w", err)
		}
		currentRoot = [sha256.Size]byte(snap.Hash)
	}

	mgr := &Manager{
		tree:        tree,
		syncCtl:     ctl,
		currentRoot: currentRoot,
	}
	if initVer > 0 {
		mgr.durableSize.Store(uint64(initVer))
	}
	mgr.exact.Store(initExact)
	return mgr, nil
}

// NewMem creates a new in-memory MPT manager.
func NewMem() *Manager {
	mgr, _ := Open("")
	return mgr
}

// RLock acquires the read lock.
func (m *Manager) RLock() { m.treeMu.RLock() }

// RUnlock releases the read lock.
func (m *Manager) RUnlock() { m.treeMu.RUnlock() }

// Lock acquires the persistence and tree write locks.
func (m *Manager) Lock() {
	m.writeMu.Lock()
	m.treeMu.Lock()
}

// Unlock releases the tree and persistence write locks.
func (m *Manager) Unlock() {
	m.treeMu.Unlock()
	m.writeMu.Unlock()
}

// Root returns the current MPT root hash.
func (m *Manager) Root() [sha256.Size]byte {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.currentRoot
}

// PredictBatch calculates the MPT root hash that would result from applying a pre-validated Batch without modifying the tree.
func (m *Manager) PredictBatch(batch Batch) ([sha256.Size]byte, error) {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()

	if !m.exact.Load() {
		return [sha256.Size]byte{}, torchmpt.ErrModifiedTree
	}
	if len(batch.changes) == 0 {
		return m.currentRoot, nil
	}

	hash, err := m.tree.Predict(batch.changes)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Predict failed: %w", err)
	}
	return [sha256.Size]byte(hash), nil
}

// PredictKeys calculates the MPT root hash that would result from applying variable-length key mutations without modifying the tree.
func (m *Manager) PredictKeys(mutations map[string][sha256.Size]byte) ([sha256.Size]byte, error) {
	batch, err := PrepareBatch(mutations)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return m.PredictBatch(batch)
}

// SetKeyBatch applies variable-length key mutations directly to the working tree under writeMu without creating a snapshot.
func (m *Manager) SetKeyBatch(mutations map[string][sha256.Size]byte) error {
	if len(mutations) == 0 {
		return nil
	}
	batch, err := PrepareBatch(mutations)
	if err != nil {
		return err
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
		defer func() { m.syncCtl.deferSync = false }()
	}

	m.exact.Store(false)
	for _, kv := range batch.changes {
		if err := m.tree.Set(kv.Key, kv.Val); err != nil {
			return fmt.Errorf("tree.Set failed for key %q: %w", kv.Key, err)
		}
	}
	return nil
}

// Snap creates a snapshot at the specified version, updates currentRoot, and returns the root hash.
func (m *Manager) Snap(version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
		defer func() { m.syncCtl.deferSync = false }()
	}

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	m.exact.Store(true)
	return m.currentRoot, nil
}

// CommitBatchAndPersist executes Step 2 (in-memory mutation, journal page-cache flush, and optional
// state-promotion callback under treeMu) followed immediately by Step 3 (kernel fsync under writeMu
// after releasing treeMu so concurrent readers never block on disk I/O).
func (m *Manager) CommitBatchAndPersist(batch Batch, version int64, onCommitted func(actualRoot [sha256.Size]byte)) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	treeLocked := true
	defer func() {
		if m.syncCtl != nil {
			m.syncCtl.deferSync = false
		}
		if treeLocked {
			m.treeMu.Unlock()
		}
	}()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
	}
	if len(batch.changes) > 0 {
		m.exact.Store(false)
		for _, kv := range batch.changes {
			if err := m.tree.Set(kv.Key, kv.Val); err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("tree.Set failed for key %q: %w", kv.Key, err)
			}
		}
	}

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	if err := m.tree.Sync(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Sync failed: %w", err)
	}
	actualRoot := [sha256.Size]byte(snap.Hash)
	m.currentRoot = actualRoot
	m.exact.Store(true)

	if onCommitted != nil {
		onCommitted(actualRoot)
	}

	if m.syncCtl != nil {
		m.syncCtl.deferSync = false
	}
	treeLocked = false
	m.treeMu.Unlock()

	if err := m.syncCtl.syncPending(); err != nil {
		return [sha256.Size]byte{}, err
	}
	if version > 0 {
		m.durableSize.Store(uint64(version))
	}
	return actualRoot, nil
}

// CommitKeysWithVersion applies variable-length key mutations, records the version watermark, and returns the new root hash.
func (m *Manager) CommitKeysWithVersion(mutations map[string][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	batch, err := PrepareBatch(mutations)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
		defer func() { m.syncCtl.deferSync = false }()
	}
	if len(batch.changes) > 0 {
		m.exact.Store(false)
		for _, kv := range batch.changes {
			if err := m.tree.Set(kv.Key, kv.Val); err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("tree.Set failed for key %q: %w", kv.Key, err)
			}
		}
	}
	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	m.exact.Store(true)
	return m.currentRoot, nil
}

// ProveKey generates an inclusion or non-inclusion proof for the given variable-length key.
func (m *Manager) ProveKey(key []byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.ProveKeyLocked(key)
}

// ProveKeyLocked generates an inclusion or non-inclusion proof for key without acquiring the lock (caller must hold m.RLock()).
func (m *Manager) ProveKeyLocked(key []byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	if err := ValidateCanonicalKey(key); err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	if !m.exact.Load() {
		return nil, [sha256.Size]byte{}, false, torchmpt.ErrModifiedTree
	}
	path, err := m.tree.Path(torchmpt.Key(key))
	if err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	val, ok, p, err := torchmpt.ProveLookup(torchmpt.Key(key), path)
	if err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	var vr [sha256.Size]byte
	if ok {
		if len(val) != sha256.Size {
			return nil, [sha256.Size]byte{}, false, fmt.Errorf("unexpected MPT value length %d, want %d", len(val), sha256.Size)
		}
		copy(vr[:], val)
	}
	return []byte(p), vr, ok, nil
}

// ProvePrefixLocked generates a prefix subtree proof and scans all matching keys without acquiring the lock (caller must hold m.RLock()).
// If maxKeys > 0 and the number of matching keys exceeds maxKeys, iteration aborts immediately with ErrPrefixTooManyKeys.
func (m *Manager) ProvePrefixLocked(prefix []byte, maxKeys int) (proof []byte, matches []PrefixKeyVal, err error) {
	if err := ValidateCanonicalKey(prefix); err != nil {
		return nil, nil, err
	}
	if !m.exact.Load() {
		return nil, nil, torchmpt.ErrModifiedTree
	}
	path, err := m.tree.Path(torchmpt.Key(prefix))
	if err != nil {
		return nil, nil, err
	}
	_, p, err := torchmpt.ProvePrefix(prefix, path)
	if err != nil {
		return nil, nil, err
	}

	for kv, scanErr := range m.tree.Scan(prefix) {
		if scanErr != nil {
			return nil, nil, scanErr
		}
		if maxKeys > 0 && len(matches) >= maxKeys {
			return nil, nil, fmt.Errorf("%w: prefix %q exceeded limit of %d keys", ErrPrefixTooManyKeys, prefix, maxKeys)
		}
		if len(kv.Val) != sha256.Size {
			return nil, nil, fmt.Errorf("unexpected MPT value length %d for key %q, want %d", len(kv.Val), kv.Key, sha256.Size)
		}
		var vr [sha256.Size]byte
		copy(vr[:], kv.Val)
		matches = append(matches, PrefixKeyVal{
			Key:       string(kv.Key),
			ValueRoot: vr,
		})
	}
	return []byte(p), matches, nil
}

// IsExact returns true if the MPT is at an exact committed snapshot without uncommitted SetKeyBatch mutations.
func (m *Manager) IsExact() bool {
	return m.exact.Load()
}

// PersistedSize returns the tree size corresponding to the durably synced version on disk.
func (m *Manager) PersistedSize() uint64 {
	return m.durableSize.Load()
}

// Persist flushes in-memory MPT patches into the OS page cache under treeMu (preventing races
// with concurrent Path/Scan/Predict readers) while deferring blocking kernel fsync syscalls
// until after treeMu is released.
func (m *Manager) Persist() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
	}
	syncErr := m.tree.Sync()
	v, _ := m.tree.Version()
	isExact := m.exact.Load()
	if m.syncCtl != nil {
		m.syncCtl.deferSync = false
	}
	m.treeMu.Unlock()

	if syncErr != nil {
		return syncErr
	}
	if err := m.syncCtl.syncPending(); err != nil {
		return err
	}
	if isExact && v > 0 {
		m.durableSize.Store(uint64(v))
	}
	return nil
}

// Close closes the underlying MPT files, preserving on-disk exactness without promoting un-Persisted snapshots.
func (m *Manager) Close() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = false
	}
	return errors.Join(m.syncCtl.syncPending(), m.tree.Close())
}

func cutCanonicalUvarint(b []byte) (uint64, []byte, error) {
	val, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, nil, fmt.Errorf("%w: malformed uvarint", torchmpt.ErrInvalidProof)
	}
	if n > 1 && b[n-1] == 0 {
		return 0, nil, fmt.Errorf("%w: non-canonical overlong uvarint", torchmpt.ErrInvalidProof)
	}
	return val, b[n:], nil
}

func validateProofWireBounds(root [sha256.Size]byte, hasTerminalLeaf bool, proof []byte) error {
	steps := proof
	if hasTerminalLeaf {
		if root == emptyMPTHash {
			if len(proof) != 0 {
				return fmt.Errorf("%w: expected empty proof for empty MPT", torchmpt.ErrInvalidProof)
			}
			return nil
		}

		klen, afterKLen, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if klen > uint64(len(afterKLen)) {
			return fmt.Errorf("%w: truncated terminal leaf key", torchmpt.ErrInvalidProof)
		}
		pkey := afterKLen[:klen]
		steps = afterKLen[klen:]
		if err := ValidateCanonicalKey(pkey); err != nil {
			return fmt.Errorf("%w: %w", torchmpt.ErrInvalidProof, err)
		}

		vlen, afterVLen, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if vlen > uint64(len(afterVLen)) {
			return fmt.Errorf("%w: truncated terminal leaf value", torchmpt.ErrInvalidProof)
		}
		pval := afterVLen[:vlen]
		steps = afterVLen[vlen:]
		if len(pval) != sha256.Size {
			return fmt.Errorf("%w: terminal leaf value length %d, want %d", torchmpt.ErrInvalidProof, len(pval), sha256.Size)
		}
	}

	const maxSplitBit = uint64(8 * MaxKeyLen)
	prevBit := maxSplitBit + 1
	for len(steps) > 0 {
		ub, rest, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if ub > maxSplitBit {
			return fmt.Errorf("%w: split bit %d exceeds maximum %d", torchmpt.ErrInvalidProof, ub, maxSplitBit)
		}
		if ub >= prevBit {
			return fmt.Errorf("%w: split bits not strictly decreasing (%d >= %d)", torchmpt.ErrInvalidProof, ub, prevBit)
		}
		if len(rest) < sha256.Size {
			return fmt.Errorf("%w: truncated sibling hash in path step", torchmpt.ErrInvalidProof)
		}
		steps = rest[sha256.Size:]
		prevBit = ub
	}
	return nil
}

// VerifyKey verifies an inclusion or non-inclusion proof for a variable-length key against an MPT root hash.
func VerifyKey(root [sha256.Size]byte, key []byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	if err := ValidateCanonicalKey(key); err != nil {
		return err
	}
	if err := validateProofWireBounds(root, !exists, proof); err != nil {
		return err
	}
	snap := torchmpt.Snapshot{
		Hash:    torchmpt.Hash(root),
		Version: -1,
	}
	var val []byte
	if exists {
		val = valHash[:]
	}
	return torchmpt.VerifyLookup(snap, key, val, exists, torchmpt.Proof(proof))
}

// VerifyPrefix verifies a prefix subtree proof and the completeness/soundness of matches against an MPT root hash.
func VerifyPrefix(root [sha256.Size]byte, prefix []byte, matches []PrefixKeyVal, proof []byte) error {
	if err := ValidateCanonicalKey(prefix); err != nil {
		return err
	}
	prefixStr := string(prefix)
	for i := range matches {
		k := matches[i].Key
		if err := ValidateCanonicalKey([]byte(k)); err != nil {
			return fmt.Errorf("invalid key at index %d: %w", i, err)
		}
		if !strings.HasPrefix(k, prefixStr) {
			return fmt.Errorf("%w: key %q does not have prefix %q", torchmpt.ErrInvalidProof, k, prefix)
		}
		if i > 0 && matches[i-1].Key >= k {
			return fmt.Errorf("%w: keys not in strictly increasing order at index %d (%q >= %q)", torchmpt.ErrInvalidProof, i, matches[i-1].Key, k)
		}
	}

	if err := validateProofWireBounds(root, len(matches) == 0, proof); err != nil {
		return err
	}

	subtreeHash := torchmpt.TreeHash(func(yield func(torchmpt.KeyVal) bool) {
		for i := range matches {
			if !yield(torchmpt.KeyVal{
				Key: torchmpt.Key(matches[i].Key),
				Val: torchmpt.Val(matches[i].ValueRoot[:]),
			}) {
				return
			}
		}
	})
	snap := torchmpt.Snapshot{
		Hash:    torchmpt.Hash(root),
		Version: -1,
	}
	return torchmpt.VerifyPrefix(snap, prefix, subtreeHash, torchmpt.Proof(proof))
}
