package cipclient

import (
	"os"
	"testing"
)

func TestSummarizeENIPFromPCAPVendorIdentity(t *testing.T) {
	pcapPath := "pcaps/stress/ENIP.pcap"
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not found: %s", pcapPath)
	}

	summary, err := SummarizeENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("SummarizeENIPFromPCAP failed: %v", err)
	}

	if summary.VendorID == 0 || summary.ProductName == "" {
		t.Fatalf("expected vendor identity, got vendor_id=0x%04X name=%q", summary.VendorID, summary.ProductName)
	}
	if summary.VendorID != 0x0001 {
		t.Fatalf("expected Vendor ID 0x0001, got 0x%04X", summary.VendorID)
	}
	if summary.ProductName != "1756-ENBT/A" {
		t.Fatalf("expected Product Name 1756-ENBT/A, got %q", summary.ProductName)
	}
}
