package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tturner/cipdip/internal/cipclient"
)

func TestPcapSummaryReportCoverageDump(t *testing.T) {
	prev := cipclient.CurrentProtocolProfile()
	cipclient.SetProtocolProfile(cipclient.StrictODVAProfile)
	defer cipclient.SetProtocolProfile(prev)

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     0x04,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	cipData, err := cipclient.EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest failed: %v", err)
	}
	enip := cipclient.BuildSendRRData(0x12345678, [8]byte{0x01}, cipData)
	pcapPath := writeSinglePacketPCAP(t, enip)

	t.Run("summary counts", func(t *testing.T) {
		summary, err := cipclient.SummarizeENIPFromPCAP(pcapPath)
		if err != nil {
			t.Fatalf("SummarizeENIPFromPCAP failed: %v", err)
		}
		if summary.TotalPackets != 1 || summary.ENIPPackets != 1 {
			t.Fatalf("unexpected packet counts: total=%d enip=%d", summary.TotalPackets, summary.ENIPPackets)
		}
		if summary.Requests != 1 || summary.Responses != 0 {
			t.Fatalf("unexpected request/response counts: req=%d resp=%d", summary.Requests, summary.Responses)
		}
		if summary.CIPRequests != 1 || summary.CIPResponses != 0 {
			t.Fatalf("unexpected CIP request/response counts: req=%d resp=%d", summary.CIPRequests, summary.CIPResponses)
		}
		if summary.CIPServices["Get_Attribute_Single"] != 1 {
			t.Fatalf("missing CIP service count for Get_Attribute_Single")
		}
	})

	t.Run("pcap-report output", func(t *testing.T) {
		dir := t.TempDir()
		reportPath := filepath.Join(dir, "report.md")
		flags := &pcapReportFlags{
			pcapDir:    filepath.Dir(pcapPath),
			outputFile: reportPath,
		}
		if err := runPcapReport(flags); err != nil {
			t.Fatalf("runPcapReport failed: %v", err)
		}
		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		text := string(data)
		if !strings.Contains(text, "# PCAP Summary Report") || !strings.Contains(text, "PCAP Summary:") {
			t.Fatalf("report missing expected headers")
		}
	})

	t.Run("pcap-coverage output", func(t *testing.T) {
		dir := t.TempDir()
		coveragePath := filepath.Join(dir, "coverage.md")
		flags := &pcapCoverageFlags{
			pcapDir:    filepath.Dir(pcapPath),
			outputFile: coveragePath,
		}
		if err := runPcapCoverage(flags); err != nil {
			t.Fatalf("runPcapCoverage failed: %v", err)
		}
		data, err := os.ReadFile(coveragePath)
		if err != nil {
			t.Fatalf("read coverage: %v", err)
		}
		text := string(data)
		if !strings.Contains(text, "## CIP Service Counts") {
			t.Fatalf("coverage report missing service counts")
		}
		if !strings.Contains(text, "0x0E/0x0004/0x0001/0x0001") {
			t.Fatalf("coverage report missing expected entry")
		}
	})

	t.Run("pcap-dump output", func(t *testing.T) {
		buf := &bytes.Buffer{}
		restore := captureStdout(buf)

		flags := &pcapDumpFlags{
			inputFile:  pcapPath,
			serviceHex: "0x0E",
			maxEntries: 1,
		}
		if err := runPcapDump(flags); err != nil {
			t.Fatalf("runPcapDump failed: %v", err)
		}
		restore()
		if !strings.Contains(buf.String(), "Service: 0x0E") {
			t.Fatalf("pcap-dump output missing service line")
		}
	})
}

func writeSinglePacketPCAP(t *testing.T, payload []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	packet := buildCmdTCPPacket(t, payload)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000000, 0),
		CaptureLength: len(packet),
		Length:        len(packet),
	}
	if err := writer.WritePacket(ci, packet); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	return path
}

func buildCmdTCPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12000),
		DstPort: layers.TCPPort(44818),
		Seq:     1,
		ACK:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return buf.Bytes()
}

func captureStdout(w io.Writer) func() {
	orig := os.Stdout
	r, wpipe, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = wpipe

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(w, r)
		close(done)
	}()

	return func() {
		_ = wpipe.Close()
		<-done
		os.Stdout = orig
	}
}
