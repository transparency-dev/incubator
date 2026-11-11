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
	"context"
	"fmt"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"k8s.io/klog/v2"
)

// TileReaper periodically deletes cached tile files below the Coordinator-governed SafeWatermark.
type TileReaper struct {
	watermarkFn func(context.Context) (uint64, error)
	cache       TileCache
}

// NewTileReaper creates a new TileReaper instance governed by watermarkFn (e.g. Coordinator.SafeWatermark).
func NewTileReaper(watermarkFn func(context.Context) (uint64, error), cache TileCache) *TileReaper {
	return &TileReaper{
		watermarkFn: watermarkFn,
		cache:       cache,
	}
}

func (r *TileReaper) updateDirSizeMetric() {
	if sizer, ok := r.cache.(interface{ DirSize() (int64, error) }); ok {
		if size, err := sizer.DirSize(); err == nil {
			metrics.TileCacheBytes.Set(float64(size))
		}
	}
}

func (r *TileReaper) pruneOnce(ctx context.Context) (uint64, int, error) {
	defer r.updateDirSizeMetric()

	if r.watermarkFn == nil {
		return 0, 0, nil
	}
	watermark, err := r.watermarkFn(ctx)
	if err != nil {
		return 0, 0, err
	}

	if watermark == 0 || r.cache == nil {
		return watermark, 0, nil
	}

	n, err := r.cache.PruneBefore(watermark)
	if err != nil {
		return watermark, n, fmt.Errorf("failed to prune tiles before watermark %d: %w", watermark, err)
	}

	if n > 0 {
		klog.V(1).Infof("TileReaper: pruned %d cached tiles below watermark %d", n, watermark)
	}

	return watermark, n, nil
}

// Run runs the reaper loop at the given interval until ctx is cancelled.
func (r *TileReaper) Run(ctx context.Context, interval time.Duration) error {
	r.updateDirSizeMetric()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, _, err := r.pruneOnce(ctx); err != nil {
				klog.Warningf("TileReaper pass failed: %v", err)
			}
		}
	}
}
