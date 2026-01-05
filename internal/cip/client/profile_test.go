package client

import (
	"encoding/binary"
	"testing"
)

func TestResolveProtocolProfileStrictDefault(t *testing.T) {
	profile := ResolveProtocolProfile("strict_odva", "", "", "", nil, nil, nil, "")
	if profile.Name != "strict_odva" {
		t.Fatalf("expected strict_odva profile, got %s", profile.Name)
	}
	if profile.ENIPByteOrder != binary.LittleEndian || profile.CIPByteOrder != binary.LittleEndian {
		t.Fatalf("expected little-endian defaults for strict_odva")
	}
	if !profile.IncludeCIPPathSize || !profile.IncludeCIPRespReserved || !profile.UseCPF {
		t.Fatalf("expected strict_odva defaults enabled")
	}
}

func TestResolveProtocolProfileLegacyCompat(t *testing.T) {
	profile := ResolveProtocolProfile("legacy_compat", "", "", "", nil, nil, nil, "")
	if profile.Name != "legacy_compat" {
		t.Fatalf("expected legacy_compat profile, got %s", profile.Name)
	}
	if profile.ENIPByteOrder != binary.BigEndian || profile.CIPByteOrder != binary.BigEndian {
		t.Fatalf("expected big-endian defaults for legacy_compat")
	}
	if profile.IncludeCIPPathSize || profile.IncludeCIPRespReserved || profile.UseCPF {
		t.Fatalf("expected legacy_compat defaults disabled")
	}
}

func TestResolveProtocolProfileVendorVariant(t *testing.T) {
	profile := ResolveProtocolProfile("vendor_variant", "rockwell_v32", "", "", nil, nil, nil, "")
	if profile.Name != "rockwell_v32" {
		t.Fatalf("expected vendor profile name, got %s", profile.Name)
	}
	if profile.UseCPF != true {
		t.Fatalf("expected vendor profile to use CPF")
	}

	schneider := ResolveProtocolProfile("vendor_variant", "schneider_m580", "", "", nil, nil, nil, "")
	if schneider.IncludeCIPRespReserved {
		t.Fatalf("expected schneider_m580 to disable response reserved bytes")
	}

	unknown := ResolveProtocolProfile("vendor_variant", "custom_variant", "", "", nil, nil, nil, "")
	if unknown.Name != "custom_variant" {
		t.Fatalf("expected custom variant name, got %s", unknown.Name)
	}
}

func TestResolveProtocolProfileOverrides(t *testing.T) {
	pathSize := false
	respReserved := true
	useCPF := false
	profile := ResolveProtocolProfile("strict_odva", "", "big", "little", &pathSize, &respReserved, &useCPF, "omit")
	if profile.ENIPByteOrder != binary.BigEndian || profile.CIPByteOrder != binary.LittleEndian {
		t.Fatalf("unexpected endian override")
	}
	if profile.IncludeCIPPathSize != false {
		t.Fatalf("unexpected path size override")
	}
	if profile.IncludeCIPRespReserved != true {
		t.Fatalf("unexpected response reserved override")
	}
	if profile.UseCPF != false {
		t.Fatalf("unexpected CPF override")
	}
	if profile.IOSequenceMode != "omit" {
		t.Fatalf("unexpected IOSequenceMode override")
	}
}

