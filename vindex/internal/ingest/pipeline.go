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

package ingest

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/tessera/api/layout"
)

// IngestionPipeline manages the 3-stage asynchronous leaf fetch, parallel mapping, and resequencing pipeline.
type IngestionPipeline struct {
	fetcher           TileFetcher
	cache             TileCache
	wasmHost          *wasmhost.WASMHost
	numWorkers        int
	numFetchWorkers   int
	fetchBatchBundles uint64
	bundleSize        uint64
	bundleTimeout     time.Duration
	chanCap           int
}

// DefaultPipelineChannelCapacity calculates the recommended buffer capacity for ingestion channels.
func DefaultPipelineChannelCapacity() int {
	c := runtime.GOMAXPROCS(0) * 32
	if c > 2048 {
		c = 2048
	}
	if c < 512 {
		c = 512
	}
	return c
}

// DefaultFetchWorkers returns the default number of concurrent tile fetch workers.
func DefaultFetchWorkers() int {
	return 4
}

// DefaultFetchBatchBundles returns the default number of bundles fetched per worker batch in Stage 1.
func DefaultFetchBatchBundles() int {
	return 50
}

// NewPipeline creates a new IngestionPipeline instance.
func NewPipeline(fetcher TileFetcher, cache TileCache, wasmHost *wasmhost.WASMHost, numWorkers int) *IngestionPipeline {
	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0) - 1
		if numWorkers < 1 {
			numWorkers = 1
		}
	}
	return &IngestionPipeline{
		fetcher:           fetcher,
		cache:             cache,
		wasmHost:          wasmHost,
		numWorkers:        numWorkers,
		numFetchWorkers:   DefaultFetchWorkers(),
		fetchBatchBundles: uint64(DefaultFetchBatchBundles()),
		bundleSize:        uint64(layout.EntryBundleWidth),
		bundleTimeout:     0,
		chanCap:           DefaultPipelineChannelCapacity(),
	}
}

// SetChannelCapacity sets the buffer capacity of internal pipeline channels.
func (p *IngestionPipeline) SetChannelCapacity(c int) {
	if c < 1 {
		c = 1
	}
	p.chanCap = c
}

// SetFetchWorkers sets the number of concurrent tile fetch worker goroutines.
func (p *IngestionPipeline) SetFetchWorkers(n int) {
	if n < 1 {
		n = 1
	}
	p.numFetchWorkers = n
}

// SetFetchBatchBundles sets the number of bundles fetched per worker batch in Stage 1.
func (p *IngestionPipeline) SetFetchBatchBundles(n int) {
	if n < 1 {
		n = 1
	}
	p.fetchBatchBundles = uint64(n)
}

// StreamBatches streams ordered MappedBatch items in range [fromLeafIdx, targetSize) with zero Pebble WAL writes.
func (p *IngestionPipeline) StreamBatches(ctx context.Context, fromLeafIdx, targetSize uint64) (<-chan *MappedBatch, <-chan error) {
	chanCap := p.chanCap
	if chanCap <= 0 {
		chanCap = DefaultPipelineChannelCapacity()
	}
	outBatches := make(chan *MappedBatch, chanCap)
	errChan := make(chan error, 1)

	if fromLeafIdx >= targetSize {
		close(outBatches)
		close(errChan)
		return outBatches, errChan
	}

	pipeCtx, cancelPipe := context.WithCancel(ctx)

	var (
		errMu    sync.Mutex
		firstErr error
	)
	recordError := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancelPipe()
	}

	leafBundleChan := make(chan *LeafBundle, chanCap)
	unorderedBatchChan := make(chan *MappedBatch, chanCap)

	var (
		fetchWg sync.WaitGroup
		mapWg   sync.WaitGroup
		reseqWg sync.WaitGroup
	)

	// Stage 1: TileFetcher & Cache
	numFetchWorkers := p.numFetchWorkers
	if numFetchWorkers <= 0 {
		numFetchWorkers = 1
	}
	startBundle := fromLeafIdx / p.bundleSize
	endBundle := (targetSize + p.bundleSize - 1) / p.bundleSize
	nextBundleIdx := startBundle
	batchBundles := p.fetchBatchBundles
	if batchBundles == 0 {
		batchBundles = uint64(DefaultFetchBatchBundles())
	}

	for w := 0; w < numFetchWorkers; w++ {
		fetchWg.Add(1)
		go func() {
			defer fetchWg.Done()
			var pendingCached *LeafBundle
			defer func() {
				if pendingCached != nil {
					pendingCached.Release()
				}
			}()
			for {
				startB := atomic.AddUint64(&nextBundleIdx, batchBundles) - batchBundles
				if startB >= endBundle {
					return
				}
				endB := startB + batchBundles
				if endB > endBundle {
					endB = endBundle
				}

				currIdx := startB * p.bundleSize
				if currIdx < fromLeafIdx {
					currIdx = fromLeafIdx
				}
				taskEndIdx := endB * p.bundleSize
				if taskEndIdx > targetSize {
					taskEndIdx = targetSize
				}

				for currIdx < taskEndIdx {
					select {
					case <-pipeCtx.Done():
						return
					default:
					}

					bundleIdx := currIdx / p.bundleSize
					var bundle *LeafBundle
					if pendingCached != nil {
						if pendingCached.BundleIdx == bundleIdx {
							bundle = pendingCached
							pendingCached = nil
						} else {
							pendingCached.Release()
							pendingCached = nil
						}
					}
					if bundle == nil && p.cache != nil {
						if b, err := p.cache.GetBundle(bundleIdx); err == nil && b != nil {
							bEnd := b.StartLeafIdx + uint64(len(b.Leaves))
							if b.StartLeafIdx <= currIdx && currIdx < bEnd && (uint64(len(b.Leaves)) == p.bundleSize || bEnd >= targetSize) {
								bundle = b
							} else {
								b.Release()
							}
						}
					}

					var toEmit []*LeafBundle
					if bundle != nil {
						toEmit = []*LeafBundle{bundle}
					} else {
						if p.fetcher == nil {
							recordError(fmt.Errorf("cache miss for bundle %d with nil fetcher", bundleIdx))
							return
						}
						fetchEndIdx := taskEndIdx
						if p.cache != nil {
							for probeIdx := (bundleIdx + 1) * p.bundleSize; probeIdx < taskEndIdx; probeIdx += p.bundleSize {
								probeBundleIdx := probeIdx / p.bundleSize
								if b, err := p.cache.GetBundle(probeBundleIdx); err == nil && b != nil {
									bEnd := b.StartLeafIdx + uint64(len(b.Leaves))
									validCached := b.StartLeafIdx <= probeIdx && probeIdx < bEnd && (uint64(len(b.Leaves)) == p.bundleSize || bEnd >= targetSize)
									if validCached {
										pendingCached = b
										fetchEndIdx = probeIdx
										break
									}
									b.Release()
								}
							}
						}
						count := fetchEndIdx - currIdx
						bundles, err := p.fetcher.FetchTiles(pipeCtx, currIdx, count)
						if err != nil {
							recordError(fmt.Errorf("fetch tiles [%d, %d) failed: %w", currIdx, currIdx+count, err))
							return
						}
						if len(bundles) == 0 {
							recordError(fmt.Errorf("fetch tiles [%d, %d) returned 0 bundles", currIdx, currIdx+count))
							return
						}
						for i, b := range bundles {
							if p.cache != nil {
								if err := p.cache.PutBundle(b); err != nil {
									for _, rem := range bundles[i:] {
										rem.Release()
									}
									recordError(fmt.Errorf("failed to cache bundle %d: %w", b.BundleIdx, err))
									return
								}
							}
						}
						toEmit = bundles
					}

					for i, b := range toEmit {
						select {
						case <-pipeCtx.Done():
							for _, rem := range toEmit[i:] {
								rem.Release()
							}
							return
						case leafBundleChan <- b:
						}
						nextIdx := b.StartLeafIdx + uint64(len(b.Leaves))
						if nextIdx <= currIdx {
							nextIdx = (b.BundleIdx + 1) * p.bundleSize
						}
						currIdx = nextIdx
					}
				}
			}
		}()
	}

	go func() {
		fetchWg.Wait()
		close(leafBundleChan)
	}()

	// Stage 2: MapWorkerPool
	for i := 0; i < p.numWorkers; i++ {
		mapWg.Add(1)
		go func() {
			defer mapWg.Done()

			workerCtx, cancelWorker := context.WithCancel(pipeCtx)
			defer cancelWorker()

			if p.wasmHost == nil {
				recordError(errors.New("nil WASM host"))
				return
			}
			runner, err := p.wasmHost.NewRunner(workerCtx)
			if err != nil {
				recordError(fmt.Errorf("failed to create worker wasm runner: %w", err))
				return
			}
			defer func() { _ = runner.Close(context.Background()) }()

			for bundle := range leafBundleChan {
				select {
				case <-pipeCtx.Done():
					bundle.Release()
					return
				default:
				}

				startIdx := bundle.StartLeafIdx
				if fromLeafIdx > startIdx {
					startIdx = fromLeafIdx
				}
				endIdx := bundle.StartLeafIdx + uint64(len(bundle.Leaves))
				if targetSize < endIdx {
					endIdx = targetSize
				}
				if startIdx >= endIdx {
					bundle.Release()
					continue
				}

				bundleCtx := workerCtx
				var bundleCancel context.CancelFunc
				if p.bundleTimeout > 0 {
					bundleCtx, bundleCancel = context.WithTimeout(workerCtx, p.bundleTimeout)
				}

				subLeaves := bundle.Leaves[startIdx-bundle.StartLeafIdx : endIdx-bundle.StartLeafIdx]
				keyIndices := make(map[string][]uint64, len(subLeaves))
				var mapErr error
				var numLeavesMapped int
				var totalKeysGenerated int
				startMapBundle := time.Now()

				bundleResults, err := runner.MapBundle(bundleCtx, subLeaves)
				if err != nil {
					metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
					if bundleCancel != nil && bundleCtx.Err() == context.DeadlineExceeded && pipeCtx.Err() == nil {
						mapErr = fmt.Errorf("mapper timed out on bundle %d: %w", bundle.BundleIdx, context.DeadlineExceeded)
					} else {
						mapErr = fmt.Errorf("mapper failed on bundle %d: %w", bundle.BundleIdx, err)
					}
				} else if len(bundleResults) != len(subLeaves) {
					metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
					mapErr = fmt.Errorf("mapper returned %d leaf results on bundle %d, want %d", len(bundleResults), bundle.BundleIdx, len(subLeaves))
				} else {
					for offset, entries := range bundleResults {
						leafIdx := startIdx + uint64(offset)
						numLeavesMapped++
						totalKeysGenerated += len(entries)

						for _, e := range entries {
							if list := keyIndices[e.Key]; len(list) > 0 && list[len(list)-1] == leafIdx {
								continue
							}
							keyIndices[e.Key] = append(keyIndices[e.Key], leafIdx)
						}
					}
				}
				if bundleCancel != nil {
					bundleCancel()
				}
				metrics.MapDurationSeconds.Observe(time.Since(startMapBundle).Seconds())

				if mapErr != nil {
					bundle.Release()
					recordError(mapErr)
					return
				}

				metrics.LeavesMappedTotal.Add(float64(numLeavesMapped))
				metrics.KeysMappedTotal.Add(float64(totalKeysGenerated))

				batch := &MappedBatch{
					BundleIdx:    bundle.BundleIdx,
					StartLeafIdx: startIdx,
					EndLeafIdx:   endIdx,
					Count:        uint32(endIdx - startIdx),
					KeyIndices:   keyIndices,
				}
				bundle.Release()

				select {
				case <-pipeCtx.Done():
					return
				case unorderedBatchChan <- batch:
				}
			}
		}()
	}

	go func() {
		mapWg.Wait()
		for bundle := range leafBundleChan {
			bundle.Release()
		}
		close(unorderedBatchChan)
	}()

	// Stage 3: Resequencer
	reseqWg.Add(1)
	go func() {
		defer reseqWg.Done()
		defer close(outBatches)

		expectedStartLeafIdx := fromLeafIdx
		pq := &batchPriorityQueue{}
		heap.Init(pq)

		for {
			select {
			case <-pipeCtx.Done():
				return
			case batch, ok := <-unorderedBatchChan:
				if !ok {
					if expectedStartLeafIdx != targetSize || pq.Len() > 0 {
						if ctx.Err() != nil {
							recordError(ctx.Err())
						} else if pipeCtx.Err() == nil {
							recordError(fmt.Errorf("resequencer incomplete: processed up to leaf %d, want target size %d (%d batches unconsumed)", expectedStartLeafIdx, targetSize, pq.Len()))
						}
					}
					return
				}

				heap.Push(pq, batch)
				for pq.Len() > 0 && (*pq)[0].StartLeafIdx == expectedStartLeafIdx {
					nextBatch := heap.Pop(pq).(*MappedBatch)
					select {
					case <-pipeCtx.Done():
						return
					case outBatches <- nextBatch:
					}
					expectedStartLeafIdx = nextBatch.EndLeafIdx
				}
			}
		}
	}()

	// Stage 4: Completion barrier
	go func() {
		fetchWg.Wait()
		mapWg.Wait()
		reseqWg.Wait()
		cancelPipe()

		errMu.Lock()
		if firstErr != nil {
			errChan <- firstErr
		} else if ctx.Err() != nil {
			errChan <- ctx.Err()
		}
		errMu.Unlock()
		close(errChan)
	}()

	return outBatches, errChan
}

type batchPriorityQueue []*MappedBatch

func (pq batchPriorityQueue) Len() int           { return len(pq) }
func (pq batchPriorityQueue) Less(i, j int) bool { return pq[i].StartLeafIdx < pq[j].StartLeafIdx }
func (pq batchPriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }
func (pq *batchPriorityQueue) Push(x any)        { *pq = append(*pq, x.(*MappedBatch)) }
func (pq *batchPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}
