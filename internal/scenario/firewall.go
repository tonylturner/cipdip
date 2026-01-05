package scenario

// Firewall scenarios: vendor-specific DPI regression packs.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

type FirewallScenario struct {
	Vendor string
}

type firewallStep struct {
	ID          string
	Tags        []string
	UseReads    bool
	UseWrites   bool
	UseCustom   bool
	UseEdges    bool
	UseIO       bool
	Required    bool
	Description string
}

func (s *FirewallScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	vendor := strings.ToLower(strings.TrimSpace(s.Vendor))
	if vendor == "" {
		return fmt.Errorf("firewall scenario missing vendor")
	}
	params.Logger.Info("Starting firewall_%s scenario", vendor)

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
	defer client.Disconnect(ctx)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	vendors := []string{vendor}
	if vendor == "pack" {
		vendors = []string{"hirschmann", "moxa", "dynics"}
	}

	stepCount := 0
	for _, runVendor := range vendors {
		steps := firewallStepsForVendor(runVendor)
		if len(steps) == 0 {
			return fmt.Errorf("firewall_%s has no steps configured", runVendor)
		}
		for _, step := range steps {
			stepName := fmt.Sprintf("firewall_%s:%s", runVendor, step.ID)
			params.Logger.Info("Running %s (%s)", stepName, step.Description)

			readTargets := filterTargetsByTags(cfg.ReadTargets, step.Tags, runVendor)
			writeTargets := filterTargetsByTags(cfg.WriteTargets, step.Tags, runVendor)
			customTargets := filterTargetsByTags(cfg.CustomTargets, step.Tags, runVendor)
			edgeTargets := filterEdgeTargetsByTags(cfg.EdgeTargets, step.Tags, runVendor)
			ioTargets := filterIOByTags(cfg.IOConnections, step.Tags, runVendor)

			if step.UseIO && len(ioTargets) > 0 {
				if err := runFirewallIO(ctx, client, ioTargets, params, stepName, cfg.ScenarioJitterMs, rng); err != nil {
					return err
				}
			}

			if step.UseReads || step.UseWrites || step.UseCustom || step.UseEdges {
				if err := runFirewallRequests(ctx, client, readTargets, writeTargets, customTargets, edgeTargets, params, stepName, cfg.ScenarioJitterMs, rng); err != nil {
					return err
				}
			}

			if step.Required && len(readTargets) == 0 && len(writeTargets) == 0 && len(customTargets) == 0 && len(edgeTargets) == 0 && len(ioTargets) == 0 {
				return fmt.Errorf("%s has no tagged targets; check config tags", stepName)
			}

			stepCount++
		}
	}

	if stepCount == 0 {
		return fmt.Errorf("firewall_%s has no runnable steps; check config tags", vendor)
	}

	return nil
}

func firewallStepsForVendor(vendor string) []firewallStep {
	common := []firewallStep{
		{
			ID:          "tc-enip-001-explicit",
			Tags:        []string{"tc-enip-001-explicit"},
			UseReads:    true,
			UseWrites:   true,
			UseCustom:   true,
			UseEdges:    true,
			Required:    true,
			Description: "Explicit messaging coverage (TCP/44818)",
		},
		{
			ID:          "tc-enip-001-implicit",
			Tags:        []string{"tc-enip-001-implicit"},
			UseIO:       true,
			Required:    false,
			Description: "Implicit I/O coverage (UDP/2222)",
		},
		{
			ID:          "tc-enip-002-violation",
			Tags:        []string{"tc-enip-002-violation"},
			UseCustom:   true,
			UseEdges:    true,
			Required:    false,
			Description: "Unmatched/violating traffic handling",
		},
		{
			ID:          "tc-enip-003-reset",
			Tags:        []string{"tc-enip-003-reset"},
			UseCustom:   true,
			UseEdges:    true,
			Required:    false,
			Description: "TCP reset behavior on blocked traffic",
		},
		{
			ID:          "tc-enip-004-allowlist",
			Tags:        []string{"tc-enip-004-allowlist"},
			UseCustom:   true,
			UseEdges:    true,
			Required:    false,
			Description: "Class/Service allowlisting granularity",
		},
	}

	switch vendor {
	case "hirschmann":
		return append(common,
			firewallStep{
				ID:          "tc-hirsch-001-pccc",
				Tags:        []string{"tc-hirsch-001-pccc"},
				UseCustom:   true,
				UseEdges:    true,
				Required:    false,
				Description: "Embedded PCCC toggle regression",
			},
			firewallStep{
				ID:          "tc-hirsch-002-wildcard",
				Tags:        []string{"tc-hirsch-002-wildcard"},
				UseCustom:   true,
				UseEdges:    true,
				Required:    false,
				Description: "Wildcard vs explicit service codes",
			},
		)
	case "moxa":
		return append(common,
			firewallStep{
				ID:          "tc-moxa-001-default-action",
				Tags:        []string{"tc-moxa-001-default-action"},
				UseCustom:   true,
				UseEdges:    true,
				Required:    false,
				Description: "Accept/Monitor/Reset default action",
			},
		)
	case "dynics":
		return append(common,
			firewallStep{
				ID:          "tc-dyn-001-learn",
				Tags:        []string{"tc-dyn-001-learn"},
				UseReads:    true,
				UseWrites:   true,
				UseCustom:   true,
				UseEdges:    true,
				Required:    false,
				Description: "Learn-mode baseline capture",
			},
			firewallStep{
				ID:          "tc-dyn-001-novel",
				Tags:        []string{"tc-dyn-001-novel"},
				UseCustom:   true,
				UseEdges:    true,
				Required:    false,
				Description: "Learn-mode novelty rejection",
			},
		)
	default:
		return common
	}
}

func runFirewallRequests(ctx context.Context, client cipclient.Client, reads, writes, customs []config.CIPTarget, edges []config.EdgeTarget, params ScenarioParams, scenarioName string, jitterMs int, rng *rand.Rand) error {
	writeCounters := make(map[string]int64)
	writeToggles := make(map[string]bool)
	var lastOp time.Time

	for _, target := range reads {
		applyScenarioJitter(jitterMs, rng)
		path := cipclient.CIPPath{
			Class:     target.Class,
			Instance:  target.Instance,
			Attribute: target.Attribute,
			Name:      target.Name,
		}
		start := time.Now()
		resp, err := client.ReadAttribute(ctx, path)
		rtt := time.Since(start).Seconds() * 1000

		success := err == nil && resp.Status == 0
		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    scenarioName,
			TargetType:  params.TargetType,
			Operation:   metrics.OperationRead,
			TargetName:  target.Name,
			ServiceCode: fmt.Sprintf("0x%02X", uint8(cipclient.CIPServiceGetAttributeSingle)),
			Success:     success,
			RTTMs:       rtt,
			JitterMs:    computeJitterMs(&lastOp, params.Interval),
			Status:      resp.Status,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)
	}

	for _, target := range customs {
		applyScenarioJitter(jitterMs, rng)
		serviceCode, err := serviceCodeForTarget(target.Service, target.ServiceCode)
		if err != nil {
			return err
		}
		req := cipclient.CIPRequest{
			Service: serviceCode,
			Path: cipclient.CIPPath{
				Class:     target.Class,
				Instance:  target.Instance,
				Attribute: target.Attribute,
				Name:      target.Name,
			},
		}
		req, err = applyTargetPayload(req, target.PayloadType, target.PayloadParams, target.RequestPayloadHex)
		if err != nil {
			return fmt.Errorf("custom target %s payload: %w", target.Name, err)
		}

		start := time.Now()
		resp, err := client.InvokeService(ctx, req)
		rtt := time.Since(start).Seconds() * 1000

		success := err == nil && resp.Status == 0
		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    scenarioName,
			TargetType:  params.TargetType,
			Operation:   metrics.OperationCustom,
			TargetName:  target.Name,
			ServiceCode: fmt.Sprintf("0x%02X", uint8(serviceCode)),
			Success:     success,
			RTTMs:       rtt,
			JitterMs:    computeJitterMs(&lastOp, params.Interval),
			Status:      resp.Status,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)
	}

	for _, target := range writes {
		applyScenarioJitter(jitterMs, rng)
		path := cipclient.CIPPath{
			Class:     target.Class,
			Instance:  target.Instance,
			Attribute: target.Attribute,
			Name:      target.Name,
		}
		value := generateWriteValue(target, writeCounters, writeToggles)

		valueBytes := make([]byte, 4)
		order := cipclient.CurrentProtocolProfile().CIPByteOrder
		order.PutUint32(valueBytes, uint32(value))

		start := time.Now()
		resp, err := client.WriteAttribute(ctx, path, valueBytes)
		rtt := time.Since(start).Seconds() * 1000

		success := err == nil && resp.Status == 0
		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    scenarioName,
			TargetType:  params.TargetType,
			Operation:   metrics.OperationWrite,
			TargetName:  target.Name,
			ServiceCode: fmt.Sprintf("0x%02X", uint8(cipclient.CIPServiceSetAttributeSingle)),
			Success:     success,
			RTTMs:       rtt,
			JitterMs:    computeJitterMs(&lastOp, params.Interval),
			Status:      resp.Status,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)
	}

	for _, target := range edges {
		applyScenarioJitter(jitterMs, rng)
		serviceCode, err := serviceCodeForTarget(target.Service, target.ServiceCode)
		if err != nil {
			return err
		}
		req := cipclient.CIPRequest{
			Service: serviceCode,
			Path: cipclient.CIPPath{
				Class:     target.Class,
				Instance:  target.Instance,
				Attribute: target.Attribute,
				Name:      target.Name,
			},
		}
		req, err = applyTargetPayload(req, target.PayloadType, target.PayloadParams, target.RequestPayloadHex)
		if err != nil {
			return fmt.Errorf("edge target %s payload: %w", target.Name, err)
		}

		start := time.Now()
		resp, err := client.InvokeService(ctx, req)
		rtt := time.Since(start).Seconds() * 1000

		outcome := classifyOutcome(err, resp.Status)
		success := err == nil && resp.Status == 0

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:       time.Now(),
			Scenario:        scenarioName,
			TargetType:      params.TargetType,
			Operation:       metrics.OperationCustom,
			TargetName:      target.Name,
			ServiceCode:     fmt.Sprintf("0x%02X", uint8(serviceCode)),
			Success:         success,
			RTTMs:           rtt,
			JitterMs:        computeJitterMs(&lastOp, params.Interval),
			Status:          resp.Status,
			Error:           errorMsg,
			Outcome:         outcome,
			ExpectedOutcome: target.ExpectedOutcome,
		}
		params.MetricsSink.Record(metric)
	}

	return nil
}

func runFirewallIO(ctx context.Context, client cipclient.Client, ioConns []config.IOConnectionConfig, params ScenarioParams, scenarioName string, jitterMs int, rng *rand.Rand) error {
	for _, connCfg := range ioConns {
		applyScenarioJitter(jitterMs, rng)

		transport := connCfg.Transport
		if transport == "" {
			transport = "udp"
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

		conn, err := client.ForwardOpen(ctx, connParams)
		metric := metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   scenarioName,
			TargetType: params.TargetType,
			Operation:  metrics.OperationForwardOpen,
			TargetName: connCfg.Name,
			Success:    err == nil,
		}
		if err != nil {
			metric.Error = err.Error()
			params.MetricsSink.Record(metric)
			continue
		}
		params.MetricsSink.Record(metric)

		oToTData := make([]byte, connCfg.OToTSizeBytes)
		if len(oToTData) >= 4 {
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			order.PutUint32(oToTData, uint32(time.Now().UnixNano()))
		} else if len(oToTData) > 0 {
			oToTData[0] = byte(time.Now().UnixNano())
		}

		start := time.Now()
		err = client.SendIOData(ctx, conn, oToTData)
		rtt := time.Since(start).Seconds() * 1000
		metric = metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   scenarioName,
			TargetType: params.TargetType,
			Operation:  metrics.OperationOTToTSend,
			TargetName: connCfg.Name,
			Success:    err == nil,
			RTTMs:      rtt,
		}
		if err != nil {
			metric.Error = err.Error()
		}
		params.MetricsSink.Record(metric)

		start = time.Now()
		_, err = client.ReceiveIOData(ctx, conn)
		rtt = time.Since(start).Seconds() * 1000
		metric = metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   scenarioName,
			TargetType: params.TargetType,
			Operation:  metrics.OperationTToORecv,
			TargetName: connCfg.Name,
			Success:    err == nil,
			RTTMs:      rtt,
		}
		if err != nil {
			metric.Error = err.Error()
		}
		params.MetricsSink.Record(metric)

		err = client.ForwardClose(ctx, conn)
		metric = metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   scenarioName,
			TargetType: params.TargetType,
			Operation:  metrics.OperationForwardClose,
			TargetName: connCfg.Name,
			Success:    err == nil,
		}
		if err != nil {
			metric.Error = err.Error()
		}
		params.MetricsSink.Record(metric)
	}

	return nil
}

func applyScenarioJitter(jitterMs int, rng *rand.Rand) {
	if jitterMs <= 0 || rng == nil {
		return
	}
	delay := time.Duration(rng.Intn(jitterMs+1)) * time.Millisecond
	if delay > 0 {
		time.Sleep(delay)
	}
}

func generateWriteValue(target config.CIPTarget, counters map[string]int64, toggles map[string]bool) int64 {
	switch target.Pattern {
	case "increment":
		val := counters[target.Name]
		counters[target.Name] = val + 1
		return val
	case "toggle":
		val := toggles[target.Name]
		toggles[target.Name] = !val
		if val {
			return 1
		}
		return 0
	case "constant":
		return target.InitialValue
	default:
		val := counters[target.Name]
		counters[target.Name] = val + 1
		return val
	}
}

func filterTargetsByTags(targets []config.CIPTarget, tags []string, vendor string) []config.CIPTarget {
	if len(tags) == 0 {
		return nil
	}
	out := make([]config.CIPTarget, 0, len(targets))
	for _, target := range targets {
		if hasTags(target.Tags, tags, vendor) {
			out = append(out, target)
		}
	}
	return out
}

func filterEdgeTargetsByTags(targets []config.EdgeTarget, tags []string, vendor string) []config.EdgeTarget {
	if len(tags) == 0 {
		return nil
	}
	out := make([]config.EdgeTarget, 0, len(targets))
	for _, target := range targets {
		if hasTags(target.Tags, tags, vendor) {
			out = append(out, target)
		}
	}
	return out
}

func filterIOByTags(conns []config.IOConnectionConfig, tags []string, vendor string) []config.IOConnectionConfig {
	if len(tags) == 0 {
		return nil
	}
	out := make([]config.IOConnectionConfig, 0, len(conns))
	for _, conn := range conns {
		if hasTags(conn.Tags, tags, vendor) {
			out = append(out, conn)
		}
	}
	return out
}

func hasTags(tags []string, required []string, vendor string) bool {
	if len(required) == 0 {
		return false
	}
	if len(tags) == 0 {
		return false
	}
	tagSet := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tagSet[strings.ToLower(tag)] = struct{}{}
	}
	if vendor != "" {
		if _, ok := tagSet[strings.ToLower(vendor)]; !ok {
			return false
		}
	}
	for _, req := range required {
		req = strings.ToLower(req)
		if _, ok := tagSet[req]; !ok {
			return false
		}
	}
	return true
}
