package core

import (
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/tonylturner/cipdip/internal/config"
)

func resolveFaultPolicy(cfg *config.ServerConfig) faultPolicy {
	seed := cfg.Server.RNGSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	chunkMin := cfg.Faults.TCP.ChunkMin
	chunkMax := cfg.Faults.TCP.ChunkMax
	if chunkMin == 0 {
		chunkMin = 1
	}
	if chunkMax == 0 {
		chunkMax = 4
	}
	if chunkMax < chunkMin {
		chunkMax = chunkMin
	}

	return faultPolicy{
		enabled:         cfg.Faults.Enable,
		latencyBase:     time.Duration(cfg.Faults.Latency.BaseDelayMs) * time.Millisecond,
		latencyJitter:   time.Duration(cfg.Faults.Latency.JitterMs) * time.Millisecond,
		spikeEveryN:     cfg.Faults.Latency.SpikeEveryN,
		spikeDelay:      time.Duration(cfg.Faults.Latency.SpikeDelayMs) * time.Millisecond,
		dropEveryN:      cfg.Faults.Reliability.DropResponseEveryN,
		dropPct:         cfg.Faults.Reliability.DropResponsePct,
		closeEveryN:     cfg.Faults.Reliability.CloseConnectionEveryN,
		stallEveryN:     cfg.Faults.Reliability.StallResponseEveryN,
		chunkWrites:     cfg.Faults.TCP.ChunkWrites,
		chunkMin:        chunkMin,
		chunkMax:        chunkMax,
		interChunkDelay: time.Duration(cfg.Faults.TCP.InterChunkDelayMs) * time.Millisecond,
		coalesce:        cfg.Faults.TCP.CoalesceResponses,
		rng:             rand.New(rand.NewSource(seed)),
	}
}

func (s *Server) nextResponseFaultAction() responseFaultAction {
	if !s.faults.enabled {
		return responseFaultAction{
			chunked:  s.faults.chunkWrites,
			coalesce: s.faults.coalesce,
		}
	}

	s.faults.mu.Lock()
	defer s.faults.mu.Unlock()

	s.faults.responseCount++
	count := s.faults.responseCount
	delay := s.faults.latencyBase

	if s.faults.latencyJitter > 0 {
		jitter := time.Duration(s.faults.rng.Int63n(int64(s.faults.latencyJitter) + 1))
		delay += jitter
	}
	if s.faults.spikeEveryN > 0 && count%s.faults.spikeEveryN == 0 {
		delay += s.faults.spikeDelay
	}
	if s.faults.stallEveryN > 0 && count%s.faults.stallEveryN == 0 {
		stall := s.faults.spikeDelay
		if stall == 0 {
			stall = time.Second
		}
		delay += stall
	}

	drop := s.faults.dropEveryN > 0 && count%s.faults.dropEveryN == 0

	if s.faults.dropPct > 0 && s.faults.rng.Float64() < s.faults.dropPct {
		drop = true
	}
	closeConn := s.faults.closeEveryN > 0 && count%s.faults.closeEveryN == 0

	return responseFaultAction{
		drop:     drop,
		delay:    delay,
		close:    closeConn,
		chunked:  s.faults.chunkWrites,
		coalesce: s.faults.coalesce,
	}
}

func (s *Server) writeResponse(conn *net.TCPConn, remoteAddr string, resp []byte) error {
	action := s.nextResponseFaultAction()
	if action.delay > 0 {
		time.Sleep(action.delay)
	}

	if action.coalesce {
		s.coalesceMu.Lock()
		if pending, ok := s.coalesceQueue[conn]; ok && len(pending) > 0 {
			resp = append(pending, resp...)
			delete(s.coalesceQueue, conn)
		} else {
			s.coalesceQueue[conn] = append([]byte(nil), resp...)
			s.coalesceMu.Unlock()
			if action.close {
				_ = conn.Close()
				return io.EOF
			}
			return nil
		}
		s.coalesceMu.Unlock()
	}

	if action.drop {
		if action.close {
			_ = conn.Close()
			return io.EOF
		}
		return nil
	}

	if action.chunked {
		if err := s.writeChunks(conn, resp); err != nil {
			s.logger.Error("Write response error to %s: %v", remoteAddr, err)
			return err
		}
	} else {
		if _, err := conn.Write(resp); err != nil {
			s.logger.Error("Write response error to %s: %v", remoteAddr, err)
			return err
		}
	}

	if action.close {
		_ = conn.Close()
		return io.EOF
	}
	return nil
}

func (s *Server) writeChunks(conn *net.TCPConn, resp []byte) error {
	if len(resp) == 0 {
		return nil
	}
	s.faults.mu.Lock()
	chunks := s.faults.chunkMin
	if s.faults.chunkMax > s.faults.chunkMin {
		chunks = s.faults.chunkMin + s.faults.rng.Intn(s.faults.chunkMax-s.faults.chunkMin+1)
	}
	delay := s.faults.interChunkDelay
	s.faults.mu.Unlock()

	if chunks <= 1 {
		_, err := conn.Write(resp)
		return err
	}
	size := (len(resp) + chunks - 1) / chunks
	offset := 0
	for offset < len(resp) {
		end := offset + size
		if end > len(resp) {
			end = len(resp)
		}
		if _, err := conn.Write(resp[offset:end]); err != nil {
			return err
		}
		offset = end
		if delay > 0 && offset < len(resp) {
			time.Sleep(delay)
		}
	}
	return nil
}
