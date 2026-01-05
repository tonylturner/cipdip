package validation

import (
	"context"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server"
)

func TestLoopbackClientServerValidation(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:                "Loopback",
			Personality:         "adapter",
			ListenIP:            "127.0.0.1",
			TCPPort:             0,
			EnableUDPIO:         false,
			ConnectionTimeoutMs: 2000,
		},
		Protocol: config.ProtocolConfig{Mode: "strict_odva"},
		AdapterAssemblies: []config.AdapterAssemblyConfig{
			{
				Name:          "TestAssembly",
				Class:         cipclient.CIPClassAssembly,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     4,
				Writable:      true,
				UpdatePattern: "static",
			},
		},
		Faults: config.ServerFaultConfig{
			Enable: true,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  2,
				JitterMs:     1,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
		},
	}

	logger, err := logging.NewLogger(logging.LogLevelError, "")
	if err != nil {
		t.Fatalf("NewLogger error: %v", err)
	}
	defer logger.Close()

	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer error: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start server error: %v", err)
	}
	defer srv.Stop()

	addr := srv.TCPAddr()
	if addr == nil {
		t.Fatalf("TCPAddr is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := cipclient.NewClient()
	if err := client.Connect(ctx, "127.0.0.1", addr.Port); err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	defer client.Disconnect(ctx)

	validator := cipclient.NewPacketValidator(true)

	readPath := protocol.CIPPath{
		Class:     cipclient.CIPClassAssembly,
		Instance:  0x65,
		Attribute: 0x03,
	}
	readResp, err := client.ReadAttribute(ctx, readPath)
	if err != nil {
		t.Fatalf("ReadAttribute error: %v", err)
	}
	if err := validator.ValidateCIPResponse(readResp, protocol.CIPServiceGetAttributeSingle); err != nil {
		t.Fatalf("ValidateCIPResponse(ReadAttribute) error: %v", err)
	}

	writeResp, err := client.WriteAttribute(ctx, readPath, []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("WriteAttribute error: %v", err)
	}
	if err := validator.ValidateCIPResponse(writeResp, protocol.CIPServiceSetAttributeSingle); err != nil {
		t.Fatalf("ValidateCIPResponse(WriteAttribute) error: %v", err)
	}

	embeddedReq := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     cipclient.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	ucmmResp, embeddedResp, err := client.InvokeUnconnectedSend(ctx, embeddedReq, cipclient.UnconnectedSendOptions{})
	if err != nil {
		t.Fatalf("InvokeUnconnectedSend error: %v", err)
	}
	if err := validator.ValidateCIPResponse(ucmmResp, protocol.CIPServiceUnconnectedSend); err != nil {
		t.Fatalf("ValidateCIPResponse(UnconnectedSend) error: %v", err)
	}
	if err := validator.ValidateCIPResponse(embeddedResp, protocol.CIPServiceGetAttributeSingle); err != nil {
		t.Fatalf("ValidateCIPResponse(Embedded) error: %v", err)
	}

	conn, err := client.ForwardOpen(ctx, cipclient.ConnectionParams{
		Name:                  "Loopback",
		Priority:              "scheduled",
		OToTRPIMs:             20,
		TToORPIMs:             20,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		TransportClassTrigger: 3,
		Class:                 cipclient.CIPClassAssembly,
		Instance:              0x65,
	})
	if err != nil {
		t.Fatalf("ForwardOpen error: %v", err)
	}
	if conn == nil || conn.ID == 0 {
		t.Fatalf("ForwardOpen returned invalid connection")
	}
	if err := client.ForwardClose(ctx, conn); err != nil {
		t.Fatalf("ForwardClose error: %v", err)
	}
}
