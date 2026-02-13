package scenario

// PCCC scenario: Exercises PCCC typed read/write operations against
// a PCCC-personality server via Execute PCCC (service 0x4B, class 0x67).

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/pccc"
	"github.com/tonylturner/cipdip/internal/progress"
)

// PCCCScenario exercises PCCC typed read/write operations.
type PCCCScenario struct{}

// Run executes the PCCC scenario.
func (s *PCCCScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting PCCC scenario")
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		fmt.Printf("[CLIENT] Disconnecting...\n")
		client.Disconnect(ctx)
	}()

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Define PCCC operations to cycle through
	operations := []pcccOp{
		{name: "Read_N7_0", addr: "N7:0", read: true, byteCount: 2},
		{name: "Read_N7_1", addr: "N7:1", read: true, byteCount: 2},
		{name: "Write_N7_5", addr: "N7:5", read: false, writeVal: 42},
		{name: "Read_N7_5", addr: "N7:5", read: true, byteCount: 2},
		{name: "Read_T4_0_ACC", addr: "T4:0.ACC", read: true, byteCount: 2},
		{name: "Read_F8_0", addr: "F8:0", read: true, byteCount: 4},
		{name: "Echo", echo: true, echoData: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{name: "Diagnostic", diagnostic: true},
	}

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "PCCC scenario")
	defer progressBar.Finish()

	loopCount := 0
	tns := uint16(1)

	fmt.Printf("[CLIENT] Starting PCCC scenario (cycling %d operations every %dms)\n",
		len(operations), params.Interval.Milliseconds())

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("PCCC scenario completed")
			fmt.Printf("[CLIENT] Scenario completed after %d operations\n", loopCount)
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		op := operations[loopCount%len(operations)]
		start := time.Now()

		var err error
		var success bool

		if op.echo {
			success, err = s.executeEcho(ctx, client, tns, op.echoData)
		} else if op.diagnostic {
			success, err = s.executeDiagnostic(ctx, client, tns)
		} else if op.read {
			success, err = s.executeTypedRead(ctx, client, tns, op.addr, op.byteCount)
		} else {
			success, err = s.executeTypedWrite(ctx, client, tns, op.addr, op.writeVal)
		}

		rtt := time.Since(start)
		tns++

		opType := metrics.OperationRead
		if !op.read && !op.echo && !op.diagnostic {
			opType = metrics.OperationWrite
		}
		if op.echo || op.diagnostic {
			opType = metrics.OperationCustom
		}

		m := metrics.Metric{
			Timestamp:   start,
			Scenario:    "pccc",
			TargetType:  params.TargetType,
			Operation:   opType,
			TargetName:  op.name,
			ServiceCode: "0x4B",
			Success:     success,
			RTTMs:       float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			m.Error = err.Error()
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))

		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] PCCC scenario completed after %d operations\n", loopCount)
	return nil
}

type pcccOp struct {
	name       string
	addr       string
	read       bool
	byteCount  uint8
	writeVal   int16
	echo       bool
	echoData   []byte
	diagnostic bool
}

// executeTypedRead sends a PCCC typed read via Execute PCCC.
func (s *PCCCScenario) executeTypedRead(ctx context.Context, client cipclient.Client, tns uint16, addr string, byteCount uint8) (bool, error) {
	parsed, err := pccc.ParseAddress(addr)
	if err != nil {
		return false, fmt.Errorf("parse address %q: %w", addr, err)
	}

	req := pccc.TypedReadRequest(tns, parsed, byteCount)
	payload := pccc.EncodeRequest(req)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 1},
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	return resp.Status == 0, nil
}

// executeTypedWrite sends a PCCC typed write via Execute PCCC.
func (s *PCCCScenario) executeTypedWrite(ctx context.Context, client cipclient.Client, tns uint16, addr string, value int16) (bool, error) {
	parsed, err := pccc.ParseAddress(addr)
	if err != nil {
		return false, fmt.Errorf("parse address %q: %w", addr, err)
	}

	var writeData [2]byte
	binary.LittleEndian.PutUint16(writeData[:], uint16(value))

	req := pccc.TypedWriteRequest(tns, parsed, writeData[:])
	payload := pccc.EncodeRequest(req)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 1},
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	return resp.Status == 0, nil
}

// executeEcho sends a PCCC echo request.
func (s *PCCCScenario) executeEcho(ctx context.Context, client cipclient.Client, tns uint16, data []byte) (bool, error) {
	req := pccc.EchoRequest(tns, data)
	payload := pccc.EncodeRequest(req)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 1},
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	return resp.Status == 0, nil
}

// executeDiagnostic sends a PCCC diagnostic status request.
func (s *PCCCScenario) executeDiagnostic(ctx context.Context, client cipclient.Client, tns uint16) (bool, error) {
	req := pccc.DiagnosticStatusRequest(tns)
	payload := pccc.EncodeRequest(req)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 1},
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	return resp.Status == 0, nil
}
