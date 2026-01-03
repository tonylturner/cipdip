package scenario

import (
	"testing"

	"github.com/tturner/cipdip/internal/config"
)

func TestHasTags(t *testing.T) {
	if hasTags(nil, []string{"a"}, "") {
		t.Fatalf("expected false when tags empty")
	}
	if hasTags([]string{"a"}, nil, "") {
		t.Fatalf("expected false when required empty")
	}
	if hasTags([]string{"a", "b"}, []string{"a"}, "") != true {
		t.Fatalf("expected true when required tag present")
	}
	if hasTags([]string{"a", "b"}, []string{"c"}, "") {
		t.Fatalf("expected false when required tag missing")
	}
	if hasTags([]string{"a", "vendor1"}, []string{"a"}, "vendor1") != true {
		t.Fatalf("expected true when vendor tag matches")
	}
	if hasTags([]string{"a"}, []string{"a"}, "vendor1") {
		t.Fatalf("expected false when vendor tag missing")
	}
}

func TestFilterTargetsByTags(t *testing.T) {
	targets := []config.CIPTarget{
		{Name: "A", Tags: []string{"foo", "vendor1"}},
		{Name: "B", Tags: []string{"bar", "vendor1"}},
		{Name: "C", Tags: []string{"foo", "vendor2"}},
	}
	filtered := filterTargetsByTags(targets, []string{"foo"}, "vendor1")
	if len(filtered) != 1 || filtered[0].Name != "A" {
		t.Fatalf("unexpected filtered targets: %#v", filtered)
	}
}
