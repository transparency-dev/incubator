// Copyright 2025 Google LLC. All Rights Reserved.
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

// vindex contains a prototype of an in-memory verifiable index.
// It reads data from an InputLog interface, applies a MapFn to every leaf in the
// input log, and writes the mapped information out to a Write Ahead Log. Data is
// read from the WAL, and the in-memory map is built from this.
package vindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"os"
	"path"
	"slices"
	"strconv"
	"sync"
	"time"

	"filippo.io/torchwood/mpt"
	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"k8s.io/klog/v2"
)

const (
	dbLatestCheckpointKey = "latestCheckpoint"
	dbCompactRangeKey     = "compactRange"
	dbCompactRangeSizeKey = "compactRangeSize"
)

// MapFn takes the raw leaf data from a log entry and outputs the SHA256 hashes
// of the keys at which this leaf should be indexed under.
// A leaf can be recorded at any number of entries, including no entries (in which case an empty slice must be returned).
//
// MapFn is expected to consume any error states that it encounters in some way that
// makes sense to the particular ecosystem. This might mean outputting any invalid leaves
// at a known locations (e.g. all 0s), or not outputting any entry. Any panics will cause
// the mapping process to terminate.
type MapFn func([]byte) [][sha256.Size]byte

// InputLog represents a connection to the input log from which map data will be built.
// This can be a local or remote data source.
type InputLog interface {
	// Checkpoint returns the latest checkpoint committing to the input log state.
	Checkpoint(ctx context.Context) (checkpoint []byte, err error)
	// Parse unmarshals and verifies a checkpoint obtained from GetCheckpoint.
	Parse(checkpoint []byte) (*log.Checkpoint, error)
	// Leaves returns all the leaves in the range [start, end), outputting them via
	// the returned iterator. The yielded bytes MUST be the leaf preimages,
	// i.e. hashing these values should return the leaf hashes used to construct the
	// Merkle tree.
	Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error]
}

// OutputLog is where map roots are written as leaves.
type OutputLog interface {
	// GetCheckpoint returns the latest checkpoint committing to the output log state.
	Checkpoint(ctx context.Context) (checkpoint []byte, err error)
	// Parse unmarshals and verifies a checkpoint obtained from GetCheckpoint.
	Parse(checkpoint []byte) (*log.Checkpoint, error)
	// Append adds a new leaf and returns the checkpoint that commits to it.
	Append(ctx context.Context, data []byte) (idx uint64, checkpoint []byte, err error)
	// Lookup fetches the data, with a proof, at the given index and tree size.
	Lookup(ctx context.Context, idx, size uint64) ([]byte, [][sha256.Size]byte, error)
}

type Options struct {
	PersistIndex   bool
	MeterProvider  metric.MeterProvider
	ReportInterval time.Duration
}

// NewVerifiableIndex returns an IndexBuilder that pulls entries from the given inputLog, determines
// indices for each one using the mapFn, and then writes the entries out to a Write Ahead Log at the given
// path.
// Note that only one IndexBuilder should exist for any given walPath at any time. The behaviour is unspecified,
// but likely broken, if multiple processes are writing to the same file at any given time.
func NewVerifiableIndex(ctx context.Context, inputLog InputLog, mapFn MapFn, outputLog OutputLog, rootDir string, opts Options) (*VerifiableIndex, error) {
	stateDir := path.Join(rootDir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	db, err := pebble.Open(stateDir, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("pebble.Open(): %v", err)
	}



	// Load the compact range we have calculated so far, and the size persisted. We MUST start
	// from this index in order to have properly verified the state of the input log.
	crf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	var cr *compact.Range
	var size uint64
	snap := db.NewSnapshot()
	defer logClose(snap)

	if sizeBs, sizeCloser, err := snap.Get([]byte(dbCompactRangeSizeKey)); err != nil {
		if err != pebble.ErrNotFound {
			return nil, fmt.Errorf("pebble.Get(): %v", err)
		}
		size = 0
		cr = crf.NewEmptyRange(0)
	} else {
		crBs, crCloser, err := snap.Get([]byte(dbCompactRangeKey))
		if err != nil {
			return nil, fmt.Errorf("pebble.Get(): %v", err)
		}
		defer logClose(crCloser)
		defer logClose(sizeCloser)

		size = binary.BigEndian.Uint64(sizeBs)
		crHashes := make([][]byte, len(crBs)/sha256.Size)
		for i := range crHashes {
			crHashes[i] = slices.Clone(crBs[i*sha256.Size : (i+1)*sha256.Size])
		}
		klog.V(1).Infof("Loaded compact range state from PebbleDB: size=%d, hashes=%d", size, len(crHashes))
		cr, err = crf.NewRange(0, size, crHashes)
		if err != nil {
			return nil, fmt.Errorf("NewRange: %v", err)
		}
	}

	walPath := path.Join(rootDir, "map.wal")
	wal, err := newWalWriter(walPath, size)
	if err != nil {
		return nil, err
	}
	reader, err := newWalReader(walPath)
	if err != nil {
		return nil, err
	}

	var tree mpt.Tree
	if opts.PersistIndex {
		file1 := path.Join(rootDir, "mpt.tree1")
		file2 := path.Join(rootDir, "mpt.tree2")
		disk := path.Join(rootDir, "mpt.disk")
		var openErr error
		tree, openErr = mpt.Open(file1, file2, disk)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				klog.Infof("MPT files not found, creating new MPT index tree at %s, %s, %s", file1, file2, disk)
				var createErr error
				tree, createErr = mpt.Create(file1, file2, disk)
				if createErr != nil {
					return nil, fmt.Errorf("mpt.Create(): %v", createErr)
				}
			} else {
				return nil, fmt.Errorf("mpt.Open(): %v", openErr)
			}
		}
	} else {
		tree = mpt.NewMemTree()
	}

	mp := opts.MeterProvider
	if mp == nil {
		mp = otel.GetMeterProvider()
	}
	meter := mp.Meter("github.com/transparency-dev/incubator/vindex")
	mapFnResults, err := meter.Int64Histogram(
		"vindex.map_fn.keys",
		metric.WithDescription("Number of keys returned by MapFn for each leaf"),
		metric.WithUnit("1"),
		metric.WithExplicitBucketBoundaries(0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	syncBoundaries := []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}
	buildBoundaries := []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 1.5, 2, 5, 30}

	syncFetchDuration, err := meter.Float64Histogram(
		"vindex.sync.fetch.duration",
		metric.WithDescription("Time spent fetching leaves from InputLog"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(syncBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	syncMapDuration, err := meter.Float64Histogram(
		"vindex.sync.map_fn.duration",
		metric.WithDescription("Time spent running MapFn"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(syncBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	syncProcessDuration, err := meter.Float64Histogram(
		"vindex.sync.process.duration",
		metric.WithDescription("Time spent in core mapper processing"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(syncBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	buildWalDuration, err := meter.Float64Histogram(
		"vindex.build.wal.duration",
		metric.WithDescription("Time spent reading WAL and updating in-memory map"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buildBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	buildVIndexDuration, err := meter.Float64Histogram(
		"vindex.build.vindex.duration",
		metric.WithDescription("Time spent updating the MPT"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buildBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	buildPublishDuration, err := meter.Float64Histogram(
		"vindex.build.publish.duration",
		metric.WithDescription("Time spent publishing to OutputLog"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buildBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}
	buildTotalDuration, err := meter.Float64Histogram(
		"vindex.build.total.duration",
		metric.WithDescription("Total time spent in buildMap"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buildBoundaries...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %v", err)
	}

	reportInterval := opts.ReportInterval
	if reportInterval == 0 {
		reportInterval = 5 * time.Second
	}

	mapper := &inputLogMapper{
		inputLog:            inputLog,
		mapFn:               mapFn,
		walWriter:           wal,
		db:                  db,
		mapFnResults:        mapFnResults,
		syncFetchDuration:   syncFetchDuration,
		syncMapDuration:     syncMapDuration,
		syncProcessDuration: syncProcessDuration,
		reportInterval:      reportInterval,
		r:                   cr,
	}
	b := &VerifiableIndex{
		mapper:               mapper,
		walReader:            reader,
		db:                   db,
		outputLog:            outputLog,
		vindex:               tree,
		data:                 map[[sha256.Size]byte][]uint64{},
		buildWalDuration:     buildWalDuration,
		buildVIndexDuration:  buildVIndexDuration,
		buildPublishDuration: buildPublishDuration,
		buildTotalDuration:   buildTotalDuration,
	}
	// If we persisted the index then we don't need to rebuild it
	if err := b.buildMap(ctx, !opts.PersistIndex); err != nil {
		return nil, fmt.Errorf("failed to build map: %v", err)
	}
	return b, nil
}

// inputLogMapper reads the Input Log, checking that the data matches the commitments,
// and updates the WAL and DB with the resulting information.
type inputLogMapper struct {
	inputLog            InputLog
	mapFn               MapFn
	walWriter           *walWriter
	db                  *pebble.DB
	mapFnResults        metric.Int64Histogram
	syncFetchDuration   metric.Float64Histogram
	syncMapDuration     metric.Float64Histogram
	syncProcessDuration metric.Float64Histogram
	reportInterval      time.Duration

	r *compact.Range
}

func (m *inputLogMapper) close() error {
	return m.walWriter.close()
}

// syncFromInputLog reads the latest checkpoint from the input log, and ensures that the WAL
// contains a corresponding entry for every index committed to by that checkpoint.
func (m *inputLogMapper) syncFromInputLog(ctx context.Context) error {
	rawCp, err := m.inputLog.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest checkpoint from DB: %s", err)
	}
	cp, err := m.inputLog.Parse(rawCp)
	if err != nil {
		return fmt.Errorf("failed to parse checkpoint: %s", err)
	}

	if cp.Size == 0 {
		return nil
	}

	for m.r.End() < cp.Size {
		err := func() error {
			ctx, done := context.WithCancel(ctx)
			defer done()
			r := reporter{
				lastReported: m.r.End(),
				lastReport:   time.Now(),
				treeSize:     cp.Size,
			}
			go func() {
				ticker := time.NewTicker(m.reportInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						r.report()
					case <-ctx.Done():
						return
					}
				}
			}()
			startFetch := time.Now()
			for l, err := range m.inputLog.Leaves(ctx, m.r.End(), cp.Size) {
				m.syncFetchDuration.Record(ctx, time.Since(startFetch).Seconds())

				idx := m.r.End()
				workDone := r.trackWork(idx)
				if err != nil {
					return fmt.Errorf("failed to read leaf at index %d: %v", idx, err)
				}
				if idx >= cp.Size {
					return fmt.Errorf("expected stop at cp.Size=%d, but got leaf at index=%d", cp.Size, idx)
				}

				startProcess := time.Now()
				if err := m.r.Append(rfc6962.DefaultHasher.HashLeaf(l), nil); err != nil {
					return fmt.Errorf("failed to update compact range: %v", err)
				}
				processDuration := time.Since(startProcess)

				// Apply the MapFn in as safe a way as possible. This involves trapping any panics
				// and failing gracefully.
				var hashes [][sha256.Size]byte
				var mapErr error
				startMap := time.Now()
				func() {
					defer func() {
						if r := recover(); r != nil {
							mapErr = fmt.Errorf("panic detected mapping index %d: %s", idx, r)
						}
					}()
					hashes = m.mapFn(l)
				}()
				if mapErr != nil {
					return mapErr
				}
				m.syncMapDuration.Record(ctx, time.Since(startMap).Seconds())

				m.mapFnResults.Record(ctx, int64(len(hashes)))
				workDone()

				startProcessRemainder := time.Now()
				// This is a performance tradeoff between flushing very often and allowing data to be indexed quickly,
				// and too often, and having things block on syscalls. One full level-1 tile seems to be a good tradeoff.
				const storeInterval = 256 * 256

				storeCompactRange := m.r.End()%storeInterval == 0 || m.r.End() == cp.Size
				if len(hashes) == 0 && !storeCompactRange {
					// We can skip writing out values with no hashes, as long as we're
					// not at the end of the log.
					// If we are at the end of the log, we need to write out a value as a sentinel
					// even if there are no hashes.
					processDuration += time.Since(startProcessRemainder)
					m.syncProcessDuration.Record(ctx, processDuration.Seconds())
					startFetch = time.Now()
					continue
				}
				if err := m.walWriter.append(idx, hashes); err != nil {
					return fmt.Errorf("failed to add index to entry for leaf %d: %v", idx, err)
				}
				if storeCompactRange {
					// Periodically store the validated compact range consumed so far.
					if err := m.walWriter.flush(); err != nil {
						return fmt.Errorf("failed to flush the WAL: %v", err)
					}
					if err := m.storeState(); err != nil {
						return fmt.Errorf("failed to store incremental state: %v", err)
					}
				}
				processDuration += time.Since(startProcessRemainder)
				m.syncProcessDuration.Record(ctx, processDuration.Seconds())

				startFetch = time.Now()
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if err := m.walWriter.flush(); err != nil {
		return fmt.Errorf("failed to flush: %v", err)
	}

	if m.r.End() != cp.Size {
		return fmt.Errorf("synced to tree size %d but compact range ends at %d", cp.Size, m.r.End())
	}

	// Calculate the root hash, and if it checks out, store the checkpoint to indicate safety.
	hash, err := m.r.GetRootHash(nil)
	if err != nil {
		return fmt.Errorf("failed to get root hash from compact range: %v", err)
	}
	if !bytes.Equal(hash, cp.Hash) {
		return fmt.Errorf("calculated hash for tree size %d is %x, but checkpoint commits to %x", cp.Size, hash, cp.Hash)
	}
	if err := m.db.Set([]byte(dbLatestCheckpointKey), rawCp, pebble.Sync); err != nil {
		return fmt.Errorf("failed to update state: %v", err)
	}

	klog.V(1).Infof("synced WAL to size %d", cp.Size)
	return nil
}

func (m *inputLogMapper) storeState() error {
	flatSlice := make([]byte, len(m.r.Hashes())*sha256.Size)
	for i, arr := range m.r.Hashes() {
		copy(flatSlice[i*sha256.Size:], arr[:])
	}
	b := m.db.NewBatch()
	if err := b.Set([]byte(dbCompactRangeKey), flatSlice, pebble.Sync); err != nil {
		return fmt.Errorf("failed to update state: %v", err)
	}
	if err := b.Set([]byte(dbCompactRangeSizeKey), binary.BigEndian.AppendUint64(nil, m.r.End()), pebble.Sync); err != nil {
		return fmt.Errorf("failed to update state: %v", err)
	}
	if err := m.db.Apply(b, pebble.Sync); err != nil {
		return fmt.Errorf("failed to update state: %v", err)
	}
	return nil
}

// VerifiableIndex manages reading from the input log, mapping leaves, updating the WAL,
// reading the WAL, and keeping the state of the in-memory index updated from the WAL.
type VerifiableIndex struct {
	mapper    *inputLogMapper
	walReader *walReader
	db        *pebble.DB
	outputLog OutputLog

	indexMu sync.RWMutex // covers vindex and data
	vindex  mpt.Tree
	data    map[[sha256.Size]byte][]uint64

	buildWalDuration     metric.Float64Histogram
	buildVIndexDuration  metric.Float64Histogram
	buildPublishDuration metric.Float64Histogram
	buildTotalDuration   metric.Float64Histogram

	// servingSize is the size of the input log we are serving for.
	// This a temporary workaround not having an output log, which we will eventually read to get
	// the checkpoint size.
	servingSize uint64
}

// Close ensures that any open connections are closed before returning.
func (b *VerifiableIndex) Close() error {
	return errors.Join(b.mapper.close(), b.db.Close())
}

// Lookup returns the values stored for the given key.
func (b *VerifiableIndex) Lookup(ctx context.Context, key [sha256.Size]byte) (api.LookupResponse, error) {
	// Scope the lock to be as minimal as possible
	// This looks up the indices from the in-memory map, and the proof from the vindex.
	lookupLocked := func(key [sha256.Size]byte) (mpt.Proof, []uint64, error) {
		b.indexMu.RLock()
		defer b.indexMu.RUnlock()
		_, _, proof, err := b.vindex.Prove(key)
		return proof, b.data[key], err
	}

	result := api.LookupResponse{}

	olcp, err := b.outputLog.Checkpoint(ctx)
	if err != nil {
		return result, err
	}
	result.OutputLogCP = olcp
	cp, err := b.outputLog.Parse(olcp)
	if err != nil {
		return result, err
	}
	if cp.Size == 0 {
		return result, errors.New("map is empty")
	}

	data, proof, err := b.outputLog.Lookup(ctx, cp.Size-1, cp.Size)
	if err != nil {
		return result, fmt.Errorf("failed to lookup last leaf in output log: %v", err)
	}

	// Parse the output log entry to get the input log tree size that the vindex was built from.
	mapRoot, inCp, err := UnmarshalLeaf(data)
	if err != nil {
		return result, fmt.Errorf("failed to unmarshal output leaf: %v", err)
	}
	_, size, _, err := checkpointUnsafe(inCp)
	if err != nil {
		return result, fmt.Errorf("failed to unmarshal input log checkpoint from output leaf: %v", err)
	}

	result.OutputLogLeaf = data
	result.OutputLogProof = proof

	viProof, allIndices, err := lookupLocked(key)
	if err != nil {
		return result, fmt.Errorf("failed to get inclusion proof from vindex: %v", err)
	}

	cutoff := slices.IndexFunc(allIndices, func(idx uint64) bool {
		return idx >= size
	})

	if cutoff >= 0 {
		result.IndexValue = allIndices[:cutoff]
	} else {
		result.IndexValue = allIndices
	}

	// Verify the proof. Not strictly required, but good to be robust while this code is new.
	if size > math.MaxInt64 {
		return result, fmt.Errorf("size %d exceeds MaxInt64", size)
	}
	expectFound := len(result.IndexValue) > 0
	var val []byte
	if expectFound {
		sum := sha256.New()
		for _, idx := range result.IndexValue {
			if err := binary.Write(sum, binary.BigEndian, idx); err != nil {
				return result, fmt.Errorf("failed to calculate expected value hash: %v", err)
			}
		}
		val = sum.Sum(nil)
	}

	snap := mpt.Snapshot{
		Version: int64(size),
		Hash:    mapRoot,
	}
	if err := mpt.Verify(snap, key[:], val, expectFound, viProof); err != nil {
		return result, fmt.Errorf("failed to verify proof: %v", err)
	}
	result.IndexProof = viProof

	return result, nil
}

// Update checks the input log for a new Checkpoint, and ensures that the Verifiable Index
// is updated to the corresponding size.
func (b *VerifiableIndex) Update(ctx context.Context) error {
	// TODO(mhutchinson): look for options to improve concurrency again here.
	if err := b.mapper.syncFromInputLog(ctx); err != nil {
		return err
	}
	return b.buildMap(ctx, true)
}

func (b *VerifiableIndex) publish(ctx context.Context, inCp []byte) error {
	// Construct the leaf for the output log

	if b.servingSize > math.MaxInt64 {
		return fmt.Errorf("servingSize %d exceeds MaxInt64", b.servingSize)
	}
	snap, err := b.vindex.Snap(int64(b.servingSize))
	if err != nil {
		return fmt.Errorf("Snap(): %v", err)
	}
	outIdx, rawCp, err := b.outputLog.Append(ctx, MarshalLeaf(snap.Hash, inCp))
	if err != nil {
		return fmt.Errorf("failed to append to output log: %v", err)
	}
	if klog.V(1).Enabled() {
		_, inSize, _, err := checkpointUnsafe(inCp)
		if err != nil {
			klog.Error(err)
			return nil
		}
		_, outSize, _, err := checkpointUnsafe(rawCp)
		if err != nil {
			klog.Error(err)
			return nil
		}
		klog.V(1).Infof("Published checkpoint for input log size %d into output log at index %d, and got checkpoint for output log size %d", inSize, outIdx, outSize)
	}

	return nil
}

// buildMap reads from the WAL until the file has been consumed and the map has been
// built up the provided size.
// TODO(mhutchinson): tighten the semantics here. What is the provided size?
// It does double duty: rebuilding the log to a previous size (output log): this doesn't
// need to update the OL, but normal usage should in the mutex as described below.
func (b *VerifiableIndex) buildMap(ctx context.Context, updateIndex bool) error {
	startWal := time.Now()
	updatedKeys := make(map[[sha256.Size]byte]struct{}) // Allows us to efficiently update vindex after first init

	// Load the last input log checkpoint we synced to, verified, and flushed the mapped
	// entries into the WAL.
	cpRaw, closer, err := b.db.Get([]byte(dbLatestCheckpointKey))
	if err != nil {
		if err == pebble.ErrNotFound {
			// If the key isn't there then nothing to do.
			return nil
		}
		return fmt.Errorf("failed to read latest checkpoint: %v", err)
	}
	defer logClose(closer)
	_, size, _, err := checkpointUnsafe(cpRaw)
	if err != nil {
		return fmt.Errorf("failed to parse checkpoint: %v", err)
	}

	from, to := b.servingSize, size
	if from == to {
		klog.V(1).Infof("buildMap [%d, %d): nothing to do", from, to)
		return nil
	}
	klog.V(1).Infof("buildMap [%d, %d): parsing WAL", from, to)
	for i := from; i < to; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		idx, hashes, err := b.walReader.next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			// Wait a small amount of time for more data to become available
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Locking strategy when updating the map containing actual data is to lock for each log entry
		// This more granular locking allows Lookup to still occur, and we can drop any indexes bigger than
		// the tree size.
		func() {
			b.indexMu.Lock()
			defer b.indexMu.Unlock()
			i = idx + 1
			for _, h := range hashes {
				klog.V(2).Infof("Read from WAL: index %d: %x", idx, h)
				// Add the data to the key/value map
				idxes := b.data[h]
				idxes = append(idxes, idx)
				b.data[h] = idxes
				updatedKeys[h] = struct{}{}
			}
		}()
	}
	durationWal := time.Since(startWal)
	b.buildWalDuration.Record(ctx, durationWal.Seconds())

	startVIndex := time.Now()
	if updateIndex {
		// Build the verifiable index _afterwards_ for several reasons:
		//  1) doing this incrementally leads to a lot of duplicate work for keys with multiple values
		//  2) updating the vindex needs to block lookups for the whole update of the data structure

		// Locking strategy for the verifiable index is to prevent all reads while this is being updated.
		// TODO(mhutchinson): inside the same mutex we will need to update the output log with the calculated
		// map root, and eventually witness checkpoints.
		// If this is too slow (almost certain), then we need some strategy to allow us to serve a version of
		// the vindex while also updating it. One approach could be to have 2 trees whenever we are performing
		// an update.
		klog.V(1).Infof("buildMap [%d, %d): updating %d keys in vindex", b.servingSize, size, len(updatedKeys))
		b.indexMu.Lock()
		defer b.indexMu.Unlock()
		for h := range updatedKeys {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			idxes := b.data[h]

			// Here we hash by simply appending all indices in the list and hashing that
			// TODO(mhutchinson): maybe use a log construction?
			sum := sha256.New()
			for _, idx := range idxes {
				if err := binary.Write(sum, binary.BigEndian, idx); err != nil {
					klog.Warning(err)
					return err
				}
			}

			if err := b.vindex.Set(h, [sha256.Size]byte(sum.Sum(nil))); err != nil {
				return fmt.Errorf("Insert(): %s", err)
			}
		}
	}
	durationVIndex := time.Since(startVIndex)
	b.buildVIndexDuration.Record(ctx, durationVIndex.Seconds())
	durationTotal := time.Since(startWal)

	b.servingSize = size
	klog.Infof("buildMap [%d, %d): total=%s (wal=%s, vindex=%s)", from, to, durationTotal, durationWal, durationVIndex)

	// This publish occurs within the indexMu lock intentionally.
	// This allows Lookup to always assume that the last leaf in the Output Log is the
	// one that commits to the current state of the index.
	startPublish := time.Now()
	err = b.publish(ctx, cpRaw)
	b.buildPublishDuration.Record(ctx, time.Since(startPublish).Seconds())
	b.buildTotalDuration.Record(ctx, time.Since(startWal).Seconds())
	return err
}

// checkpointUnsafe parses a checkpoint without performing any signature verification.
// This is intended to be as fast as possible, but sacrifices safety because it skips verifying
// the note signature.
//
// Parsing a checkpoint like this is only acceptable in a process where the checkpoint has already
// been verified properly, and hasn't left the TCB since being checked. In this code, the on-disk
// storage is considered to be in the TCB, and thus we can skip fully verify it a second time.
func checkpointUnsafe(rawCp []byte) (string, uint64, []byte, error) {
	parts := bytes.SplitN(rawCp, []byte{'\n'}, 4)
	if want, got := 4, len(parts); want != got {
		return "", 0, nil, fmt.Errorf("invalid checkpoint: %q", rawCp)
	}
	origin := string(parts[0])
	sizeStr := string(parts[1])
	hashStr := string(parts[2])
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return "", 0, nil, fmt.Errorf("failed to turn checkpoint size of %q into uint64: %v", sizeStr, err)
	}
	hash, err := base64.StdEncoding.DecodeString(hashStr)
	if err != nil {
		return "", 0, nil, fmt.Errorf("failed to decode hash: %v", err)
	}
	return origin, size, hash, nil
}

// Helpful wrapper to convert Closer to something that can be safely deferred (according to the linter)
func logClose(c io.Closer) {
	if err := c.Close(); err != nil {
		klog.Error(err)
	}
}

type reporter struct {
	// treeSize is fixed for the lifetime of the reporter.
	treeSize uint64

	// Fields read/written only in report()
	lastReport   time.Time
	lastReported uint64

	// Fields shared across multiple threads, protected by workedMutex
	lastWorked  uint64
	workedMutex sync.Mutex
}

func (r *reporter) report() {
	lastWorked := func() uint64 {
		r.workedMutex.Lock()
		defer r.workedMutex.Unlock()
		lw := r.lastWorked
		return lw
	}()

	elapsed := time.Since(r.lastReport)
	remaining := r.treeSize - r.lastReported - 1
	rate := float64(lastWorked-r.lastReported) / elapsed.Seconds()
	eta := time.Duration(float64(remaining)/rate) * time.Second
	klog.Infof("%.1f leaves/s, last leaf=%d (remaining: %d, ETA: %s)", rate, r.lastReported, remaining, eta)

	r.lastReport = time.Now()
	r.lastReported = lastWorked
}

func (r *reporter) trackWork(index uint64) func() {
	return func() {
		r.workedMutex.Lock()
		defer r.workedMutex.Unlock()
		r.lastWorked = index
	}
}
