package scenario

// IO scenario: Connected Class 1 I/O-style behavior

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

// IOScenario implements the io scenario
type IOScenario struct{}

// Run executes the io scenario
func (s *IOScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting io scenario")
	params.Logger.Verbose("  I/O connections: %d", len(cfg.IOConnections))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	// Check if IO connections are configured
	if len(cfg.IOConnections) == 0 {
		params.Logger.Info("No I/O connections configured, io scenario cannot run")
		return fmt.Errorf("no I/O connections configured")
	}

	// Connect to the device
	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818 // Default
		}
	}
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	// Establish I/O connections
	var ioConns []*cipclient.IOConnection
	for _, connCfg := range cfg.IOConnections {
		// Determine transport (default to "udp" for io scenario per spec)
		transport := connCfg.Transport
		if transport == "" {
			transport = "udp" // Default to UDP 2222 for I/O scenario
		}

		connParams := cipclient.ConnectionParams{
			Name:                  connCfg.Name,
			Transport:             transport,
			OToTRPIMs:             connCfg.OToTRPIMs,
			TToORPIMs:             connCfg.TToORPIMs,
			OToTSizeBytes:         connCfg.OToTSizeBytes,
			TToOSizeBytes:         connCfg.TToOSizeBytes,
			Priority:              connCfg.Priority,
			TransportClassTrigger: connCfg.TransportClassTrigger,
			Class:                 connCfg.Class,
			Instance:              connCfg.Instance,
			ConnectionPathHex:     connCfg.ConnectionPathHex,
		}

		params.Logger.Verbose("Opening I/O connection: %s (class=0x%04X, instance=0x%04X, transport=%s)",
			connCfg.Name, connCfg.Class, connCfg.Instance, connCfg.Transport)

		conn, err := client.ForwardOpen(ctx, connParams)
		if err != nil {
			params.Logger.Error("Failed to open I/O connection %s: %v", connCfg.Name, err)
			// Continue with other connections
			continue
		}

		ioConns = append(ioConns, conn)
		params.Logger.Info("Opened I/O connection: %s (ID: %d)", connCfg.Name, conn.ID)

		// Record ForwardOpen metric
		metric := metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   "io",
			TargetType: params.TargetType,
			Operation:  metrics.OperationForwardOpen,
			TargetName: connCfg.Name,
			Success:    true,
		}
		params.MetricsSink.Record(metric)
	}

	if len(ioConns) == 0 {
		return fmt.Errorf("no I/O connections could be established")
	}

	// Find shortest RPI for timing
	shortestRPI := time.Duration(cfg.IOConnections[0].OToTRPIMs) * time.Millisecond
	for _, connCfg := range cfg.IOConnections {
		rpi := time.Duration(connCfg.OToTRPIMs) * time.Millisecond
		if rpi < shortestRPI {
			shortestRPI = rpi
		}
	}

	// Use shorter of interval or shortest RPI
	loopInterval := params.Interval
	if shortestRPI < loopInterval {
		loopInterval = shortestRPI
	}

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	loopCount := 0
	startTime := time.Now()
	counter := uint32(0)

	// Main loop
	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("IO scenario completed (duration expired or cancelled)")
			break
		default:
		}

		// Check if we've exceeded duration
		if time.Now().After(deadline) {
			break
		}

		// Process each I/O connection
		for i, conn := range ioConns {
			connCfg := cfg.IOConnections[i]

			// Build O->T payload (counter pattern)
			counter++
			oToTData := make([]byte, connCfg.OToTSizeBytes)
			if len(oToTData) >= 4 {
				binary.BigEndian.PutUint32(oToTData, counter)
			} else {
				// For smaller payloads, just use the counter as a byte
				oToTData[0] = byte(counter)
			}

			// Send O->T data
			start := time.Now()
			err := client.SendIOData(ctx, conn, oToTData)
			rtt := time.Since(start).Seconds() * 1000

			success := err == nil
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			}

			metric := metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "io",
				TargetType: params.TargetType,
				Operation:  metrics.OperationOTToTSend,
				TargetName: connCfg.Name,
				Success:    success,
				RTTMs:      rtt,
				Error:      errorMsg,
			}
			params.MetricsSink.Record(metric)

			if !success {
				params.Logger.Error("SendIOData failed for %s: %v", connCfg.Name, err)
			}

			// Receive T->O data
			start = time.Now()
			tToOData, err := client.ReceiveIOData(ctx, conn)
			rtt = time.Since(start).Seconds() * 1000

			success = err == nil
			errorMsg = ""
			if err != nil {
				errorMsg = err.Error()
			}

			metric = metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "io",
				TargetType: params.TargetType,
				Operation:  metrics.OperationTToORecv,
				TargetName: connCfg.Name,
				Success:    success,
				RTTMs:      rtt,
				Error:      errorMsg,
			}
			params.MetricsSink.Record(metric)

			if !success {
				params.Logger.Verbose("ReceiveIOData failed for %s: %v", connCfg.Name, err)
			} else if len(tToOData) > 0 {
				// Store received data
				conn.LastTToODataRecv = tToOData
			}
		}

		loopCount++

		// Sleep for loop interval
		select {
		case <-ctx.Done():
			break
		case <-time.After(loopInterval):
		}
	}

	// Close all I/O connections
	for i, conn := range ioConns {
		connCfg := cfg.IOConnections[i]
		params.Logger.Verbose("Closing I/O connection: %s", connCfg.Name)

		err := client.ForwardClose(ctx, conn)
		success := err == nil
		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
			params.Logger.Error("Failed to close I/O connection %s: %v", connCfg.Name, err)
		}

		metric := metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   "io",
			TargetType: params.TargetType,
			Operation:  metrics.OperationForwardClose,
			TargetName: connCfg.Name,
			Success:    success,
			Error:      errorMsg,
		}
		params.MetricsSink.Record(metric)
	}

	elapsed := time.Since(startTime)
	params.Logger.Info("IO scenario completed: %d loops in %v", loopCount, elapsed)

	return nil
}
