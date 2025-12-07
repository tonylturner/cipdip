package capture

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Capture represents a packet capture session
type Capture struct {
	handle    *pcap.Handle
	writer    *pcapgo.Writer
	file      *os.File
	packets   []gopacket.Packet
	startTime time.Time
	stopChan  chan struct{}
	stopOnce  sync.Once
}

// StartCapture starts capturing packets on the specified interface
func StartCapture(iface string, outputFile string) (*Capture, error) {
	// Open live capture
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live capture: %w", err)
	}

	// Set filter for EtherNet/IP traffic (ports 44818, 2222)
	filter := "tcp port 44818 or udp port 44818 or udp port 2222 or tcp port 2222"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	// Create output file
	file, err := os.Create(outputFile)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("create pcap file: %w", err)
	}

	// Create pcap writer
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		file.Close()
		handle.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	c := &Capture{
		handle:    handle,
		writer:    writer,
		file:      file,
		packets:   make([]gopacket.Packet, 0),
		startTime: time.Now(),
		stopChan:  make(chan struct{}),
	}

	// Start background capture goroutine
	go c.captureLoop()

	return c, nil
}

// StartCaptureLoopback starts capturing on loopback interface
func StartCaptureLoopback(outputFile string) (*Capture, error) {
	// Get list of interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find network devices: %w", err)
	}

	// Try to find loopback interface
	var loopbackIface string
	for _, device := range devices {
		// Check if it's a loopback interface (has loopback address or name suggests it)
		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() {
				loopbackIface = device.Name
				break
			}
		}
		// Also check common names
		if loopbackIface == "" {
			name := device.Name
			if name == "lo0" || name == "lo" || name == "Loopback" || name == "Loopback Pseudo-Interface 1" {
				loopbackIface = name
				break
			}
		}
		if loopbackIface != "" {
			break
		}
	}

	if loopbackIface == "" {
		// Fallback: try common names directly
		interfaces := []string{"lo0", "lo", "Loopback", "Loopback Pseudo-Interface 1"}
		for _, iface := range interfaces {
			c, err := StartCapture(iface, outputFile)
			if err == nil {
				return c, nil
			}
		}
		return nil, fmt.Errorf("could not find loopback interface")
	}

	return StartCapture(loopbackIface, outputFile)
}

// captureLoop runs the capture loop in background
func (c *Capture) captureLoop() {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	for {
		select {
		case <-c.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet != nil {
				c.packets = append(c.packets, packet)

				// Write to pcap file
				if c.writer != nil {
					ci := packet.Metadata().CaptureInfo
					if err := c.writer.WritePacket(ci, packet.Data()); err != nil {
						// Log error but continue
						fmt.Fprintf(os.Stderr, "Warning: failed to write packet: %v\n", err)
					}
				}
			}
		}
	}
}

// Stop stops the capture and closes resources (idempotent)
func (c *Capture) Stop() error {
	c.stopOnce.Do(func() {
		close(c.stopChan)
		time.Sleep(100 * time.Millisecond) // Give capture loop time to stop

		if c.file != nil {
			c.file.Close()
			c.file = nil
		}
		if c.handle != nil {
			c.handle.Close()
			c.handle = nil
		}
	})
	return nil
}

// GetPacketCount returns the number of captured packets
func (c *Capture) GetPacketCount() int {
	return len(c.packets)
}

// GetPackets returns all captured packets
func (c *Capture) GetPackets() []gopacket.Packet {
	return c.packets
}
