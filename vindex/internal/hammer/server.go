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

package hammer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/klog/v2"
)

// ServerConfig configures the drip-feed HTTP server.
type ServerConfig struct {
	ListenAddr    string
	StorageDir    string
	DripRate      float64       // Checkpoints per second released to clients (0 = immediate)
	BurstInterval time.Duration // Interval between burst checkpoint releases (0 = steady drip)
	InitialPause  time.Duration // Initial pause duration before drip-feeding begins
}

// DripServer hosts local POSIX log tiles and publishes checkpoints to the target VIndex on a configurable schedule.
type DripServer struct {
	cfg         ServerConfig
	readCP      func(context.Context) ([]byte, error)
	publishedCP atomic.Pointer[[]byte]

	baseURL    string
	httpServer *http.Server
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closeErr   error
	wg         sync.WaitGroup
}

// NewDripServer creates a new DripServer backed by readCP (typically sequencer.ReadCheckpoint).
func NewDripServer(cfg ServerConfig, readCP func(context.Context) ([]byte, error)) *DripServer {
	return &DripServer{
		cfg:    cfg,
		readCP: readCP,
	}
}

func (s *DripServer) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cpPtr := s.publishedCP.Load()
	if cpPtr == nil || len(*cpPtr) == 0 {
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(*cpPtr)
}

// URL returns the base URL of the server.
func (s *DripServer) URL() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return "http://" + s.cfg.ListenAddr
}

// Start binds to the listening port and starts background drip scheduling.
func (s *DripServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/checkpoint", s.handleCheckpoint)
	mux.Handle("/", http.FileServer(http.Dir(s.cfg.StorageDir)))

	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}

	schedCtx, cancel := context.WithCancel(ctx)
	s.baseURL = "http://" + listener.Addr().String()
	s.cancel = cancel
	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if s.cfg.InitialPause <= 0 {
		s.refreshCheckpoint(schedCtx)
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("DripServer HTTP error: %v", err)
		}
	}()
	go func() {
		defer s.wg.Done()
		s.runDripScheduler(schedCtx)
	}()

	klog.Infof("DripServer listening on %s (storage: %s)", listener.Addr().String(), s.cfg.StorageDir)
	return nil
}

func (s *DripServer) runDripScheduler(ctx context.Context) {
	if s.cfg.InitialPause > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.InitialPause):
		}
		s.refreshCheckpoint(ctx)
	}

	var interval time.Duration
	switch {
	case s.cfg.BurstInterval > 0:
		interval = s.cfg.BurstInterval
	case s.cfg.DripRate > 0:
		interval = rateToInterval(s.cfg.DripRate, time.Millisecond)
	default:
		interval = 10 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshCheckpoint(ctx)
		}
	}
}

func (s *DripServer) refreshCheckpoint(ctx context.Context) {
	if s.readCP == nil {
		return
	}
	cp, err := s.readCP(ctx)
	if err != nil || len(cp) == 0 {
		return
	}
	if cur := s.publishedCP.Load(); cur != nil && bytes.Equal(*cur, cp) {
		return
	}
	cloned := slices.Clone(cp)
	s.publishedCP.Store(&cloned)
}

// Close gracefully stops the scheduler and HTTP server.
func (s *DripServer) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.httpServer != nil {
			sCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := s.httpServer.Shutdown(sCtx); err != nil {
				_ = s.httpServer.Close()
				s.closeErr = err
			}
			cancel()
		}
		s.wg.Wait()
	})
	return s.closeErr
}
