package scenario

// Modbus scenario: exercises Modbus function codes via CIP-tunneled
// requests (class 0x44) or describes standalone Modbus TCP operations.

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
	"github.com/tonylturner/cipdip/internal/modbus"
	"github.com/tonylturner/cipdip/internal/progress"
)

// ModbusScenario exercises Modbus function codes via CIP class 0x44.
type ModbusScenario struct{}

// Run executes the Modbus scenario.
func (s *ModbusScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting Modbus scenario")
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
		_ = client.Disconnect(ctx)
	}()

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	operations := []modbusOp{
		{name: "Read_Coils_0", fc: modbus.FcReadCoils, data: modbus.ReadCoilsRequest(0, 16), read: true},
		{name: "Read_Holding_0_10", fc: modbus.FcReadHoldingRegisters, data: modbus.ReadHoldingRegistersRequest(0, 10), read: true},
		{name: "Read_Input_0_5", fc: modbus.FcReadInputRegisters, data: modbus.ReadInputRegistersRequest(0, 5), read: true},
		{name: "Write_Single_Coil_0", fc: modbus.FcWriteSingleCoil, data: modbus.WriteSingleCoilRequest(0, true), read: false},
		{name: "Write_Single_Reg_0", fc: modbus.FcWriteSingleRegister, data: modbus.WriteSingleRegisterRequest(0, 0x1234), read: false},
		{name: "Read_Discrete_0_8", fc: modbus.FcReadDiscreteInputs, data: modbus.ReadDiscreteInputsRequest(0, 8), read: true},
		{name: "Write_Multi_Reg_0_3", fc: modbus.FcWriteMultipleRegisters,
			data: modbus.WriteMultipleRegistersRequest(0, 3, buildRegValues(3)), read: false},
		{name: "Read_Holding_0_3", fc: modbus.FcReadHoldingRegisters, data: modbus.ReadHoldingRegistersRequest(0, 3), read: true},
		{name: "Mask_Write_Reg_0", fc: modbus.FcMaskWriteRegister, data: modbus.MaskWriteRegisterRequest(0, 0x00F2, 0x0025), read: false},
	}

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Modbus scenario")
	defer progressBar.Finish()

	loopCount := 0
	var lastOp time.Time
	fmt.Printf("[CLIENT] Starting Modbus scenario (cycling %d operations every %dms)\n",
		len(operations), params.Interval.Milliseconds())

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Modbus scenario completed")
			fmt.Printf("[CLIENT] Scenario completed after %d operations\n", loopCount)
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		jitterMs := computeJitterMs(&lastOp, params.Interval)
		op := operations[loopCount%len(operations)]
		start := time.Now()

		success, err := s.executeCIPModbus(ctx, client, op)
		rtt := time.Since(start)

		opType := metrics.OperationRead
		if !op.read {
			opType = metrics.OperationWrite
		}

		m := metrics.Metric{
			Timestamp:   start,
			Scenario:    "modbus",
			TargetType:  params.TargetType,
			Operation:   opType,
			TargetName:  op.name,
			ServiceCode: "0x0E",
			Success:     success,
			RTTMs:       float64(rtt.Microseconds()) / 1000.0,
			JitterMs:    jitterMs,
		}
		if err != nil {
			m.Error = err.Error()
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))

		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] Modbus scenario completed after %d operations\n", loopCount)
	return nil
}

type modbusOp struct {
	name string
	fc   modbus.FunctionCode
	data []byte
	read bool
}

func (s *ModbusScenario) executeCIPModbus(ctx context.Context, client cipclient.Client, op modbusOp) (bool, error) {
	// Build the raw Modbus PDU (FC + data) for CIP tunnel.
	payload := make([]byte, 0, 1+len(op.data))
	payload = append(payload, byte(op.fc))
	payload = append(payload, op.data...)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 1, Attribute: 3}, // Attribute 3 = Data
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	if resp.Status != 0 {
		return false, fmt.Errorf("CIP status 0x%02X", resp.Status)
	}
	// Check if the Modbus response indicates an exception.
	if len(resp.Payload) > 0 && resp.Payload[0]&0x80 != 0 {
		return false, fmt.Errorf("modbus exception: %s", modbus.DescribeCIPModbus(resp.Payload))
	}
	return true, nil
}

func buildRegValues(count int) []byte {
	buf := make([]byte, count*2)
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint16(buf[i*2:], uint16(i+1))
	}
	return buf
}

// ModbusPipelineScenario tests Modbus TCP pipelining via CIP tunnel.
type ModbusPipelineScenario struct{}

// Run executes the Modbus pipeline scenario.
func (s *ModbusPipelineScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting Modbus pipeline scenario")

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
		_ = client.Disconnect(ctx)
	}()

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Modbus pipeline")
	defer progressBar.Finish()

	// Send batches of read requests to different register ranges.
	loopCount := 0
	batchSize := 5
	var lastOpPipeline time.Time

	fmt.Printf("[CLIENT] Starting Modbus pipeline scenario (batch=%d, interval=%dms)\n",
		batchSize, params.Interval.Milliseconds())

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Modbus pipeline scenario completed")
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		pipelineJitterMs := computeJitterMs(&lastOpPipeline, params.Interval)
		start := time.Now()
		successes := 0

		for i := 0; i < batchSize; i++ {
			addr := uint16((loopCount*batchSize + i) % 100)
			op := modbusOp{
				name: fmt.Sprintf("Pipeline_Read_%d", addr),
				fc:   modbus.FcReadHoldingRegisters,
				data: modbus.ReadHoldingRegistersRequest(addr, 1),
				read: true,
			}
			ok, _ := s.executeCIPModbus(ctx, client, op)
			if ok {
				successes++
			}
		}

		rtt := time.Since(start)
		m := metrics.Metric{
			Timestamp:  start,
			Scenario:   "modbus_pipeline",
			TargetType: params.TargetType,
			Operation:  metrics.OperationRead,
			TargetName: fmt.Sprintf("batch_%d", loopCount),
			Success:    successes == batchSize,
			RTTMs:      float64(rtt.Microseconds()) / 1000.0,
			JitterMs:   pipelineJitterMs,
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))
		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] Modbus pipeline completed after %d batches\n", loopCount)
	return nil
}

func (s *ModbusPipelineScenario) executeCIPModbus(ctx context.Context, client cipclient.Client, op modbusOp) (bool, error) {
	payload := make([]byte, 0, 1+len(op.data))
	payload = append(payload, byte(op.fc))
	payload = append(payload, op.data...)

	cipReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 1, Attribute: 3}, // Attribute 3 = Data
		Payload: payload,
	}

	resp, err := client.InvokeService(ctx, cipReq)
	if err != nil {
		return false, err
	}
	return resp.Status == 0, nil
}
