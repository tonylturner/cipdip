package core

import (
	"context"
	"fmt"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"io"
	"net"
	"testing"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/enip"
)

func TestServerIntegrationModes(t *testing.T) {
	tests := []struct {
		name string
		cfg  func() *config.ServerConfig
	}{
		{
			name: "baseline",
			cfg: func() *config.ServerConfig {
				cfg := createTestServerConfig()
				cfg.Protocol.Mode = "strict_odva"
				return cfg
			},
		},
		{
			name: "realistic",
			cfg: func() *config.ServerConfig {
				cfg := createTestServerConfig()
				cfg.Protocol.Mode = "strict_odva"
				return cfg
			},
		},
		{
			name: "dpi-torture",
			cfg: func() *config.ServerConfig {
				cfg := createTestServerConfig()
				cfg.Protocol.Mode = "strict_odva"
				cfg.Faults.Enable = true
				cfg.Faults.Latency.BaseDelayMs = 5
				cfg.Faults.Latency.JitterMs = 10
				cfg.Faults.Latency.SpikeEveryN = 10
				cfg.Faults.Latency.SpikeDelayMs = 25
				cfg.Faults.Reliability.DropResponseEveryN = 25
				cfg.Faults.Reliability.CloseConnectionEveryN = 50
				cfg.Faults.TCP.ChunkWrites = true
				cfg.Faults.TCP.ChunkMin = 2
				cfg.Faults.TCP.ChunkMax = 4
				return cfg
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg()
			logger := createTestLogger()

			srv, err := NewServer(cfg, logger)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}
			if err := srv.Start(); err != nil {
				t.Fatalf("Start failed: %v", err)
			}
			defer func() {
				if err := srv.Stop(); err != nil {
					t.Fatalf("Stop failed: %v", err)
				}
			}()

			addr := srv.tcpListener.Addr().(*net.TCPAddr)
			if addr.Port == 0 {
				t.Fatal("server did not bind a TCP port")
			}

			var sessionErr error
			if tt.name == "dpi-torture" {
				sessionErr = runRawRegisterSession(t, addr.Port)
			} else {
				sessionErr = runClientSession(t, addr.Port)
			}
			if sessionErr != nil {
				t.Fatalf("client session failed: %v", sessionErr)
			}
		})
	}
}

func runClientSession(t *testing.T, port int) error {
	t.Helper()

	client := cipclient.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, "127.0.0.1", port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	path := protocol.CIPPath{
		Class:     0x04,
		Instance:  0x65,
		Attribute: 0x03,
		Name:      "TestAssembly",
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		resp, err := client.ReadAttribute(ctx, path)
		if err == nil && resp.Status == 0x00 {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("status: 0x%02X", resp.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	return lastErr
}

func runRawRegisterSession(t *testing.T, port int) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := enip.BuildRegisterSession([8]byte{0x01})
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	header := make([]byte, 24)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder
	length := order.Uint16(header[2:4])
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("read body: %w", err)
		}
	}
	packet := append(header, body...)
	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if encap.Command != enip.ENIPCommandRegisterSession {
		return fmt.Errorf("command: 0x%04X", encap.Command)
	}
	if encap.Status != enip.ENIPStatusSuccess {
		return fmt.Errorf("status: 0x%08X", encap.Status)
	}
	if encap.SessionID == 0 {
		return fmt.Errorf("session id is 0")
	}
	return nil
}
