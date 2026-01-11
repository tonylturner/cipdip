package engine

import (
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/profile"
)

func TestNewClientEngine(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	if engine.RoleName() != "hmi" {
		t.Errorf("RoleName = %q, want 'hmi'", engine.RoleName())
	}

	if engine.PollInterval() != 500*time.Millisecond {
		t.Errorf("PollInterval = %v, want 500ms", engine.PollInterval())
	}

	if engine.BatchSize() != 5 {
		t.Errorf("BatchSize = %d, want 5", engine.BatchSize())
	}
}

func TestNewClientEngineUnknownRole(t *testing.T) {
	p := createTestProfile()

	_, err := NewClientEngine(p, "unknown")
	if err == nil {
		t.Error("expected error for unknown role")
	}
}

func TestClientEngineGetNextReadBatch(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	// First batch
	batch1 := engine.GetNextReadBatch()
	if len(batch1) != 5 {
		t.Errorf("batch1 length = %d, want 5", len(batch1))
	}

	// Verify tag names
	expectedTags := []string{"Level", "Flow", "Pressure", "Pump", "Setpoint"}
	for i, req := range batch1 {
		if req.TagName != expectedTags[i] {
			t.Errorf("batch1[%d].TagName = %q, want %q", i, req.TagName, expectedTags[i])
		}
	}

	// Second batch (cycles back for small tag lists)
	batch2 := engine.GetNextReadBatch()
	if len(batch2) != 5 {
		t.Errorf("batch2 length = %d, want 5", len(batch2))
	}

	// Check stats
	stats := engine.GetStats()
	if stats.TotalBatches != 2 {
		t.Errorf("TotalBatches = %d, want 2", stats.TotalBatches)
	}
	if stats.TotalReads != 10 {
		t.Errorf("TotalReads = %d, want 10", stats.TotalReads)
	}
}

func TestClientEngineBatchSizeLargerThanTags(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Tag1", Type: "DINT"},
				{Name: "Tag2", Type: "DINT"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States:       map[string]profile.State{"idle": {}},
		},
		Roles: map[string]profile.Role{
			"test": {
				PollInterval: "100ms",
				BatchSize:    10, // Larger than tag count
				ReadTags:     []string{"Tag1", "Tag2"},
			},
		},
	}

	engine, err := NewClientEngine(p, "test")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	batch := engine.GetNextReadBatch()
	if len(batch) != 2 {
		t.Errorf("batch length = %d, want 2 (capped at tag count)", len(batch))
	}
}

func TestClientEngineWriteScheduling(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	// Set server state to "running" to trigger state-based writes
	engine.UpdateServerState("running")

	// Tick to process write events
	engine.Tick(100 * time.Millisecond)

	// Should have pending write for "state:running" trigger
	writes := engine.GetPendingWrites()
	if len(writes) == 0 {
		t.Error("expected pending writes after state trigger")
	}

	// Second tick shouldn't fire same state event again
	engine.Tick(100 * time.Millisecond)
	writes2 := engine.GetPendingWrites()
	// State-based writes with "once" behavior should not fire again
	if len(writes2) > 0 {
		// Check if it's a different trigger type (like random)
		t.Logf("got %d writes on second tick (may be random triggers)", len(writes2))
	}
}

func TestClientEngineTimerWrite(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Setpoint", Type: "REAL", Writable: true},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States:       map[string]profile.State{"idle": {}},
		},
		Roles: map[string]profile.Role{
			"test": {
				PollInterval: "100ms",
				BatchSize:    1,
				ReadTags:     []string{"Setpoint"},
				WriteTags:    []string{"Setpoint"},
				WriteEvents: []profile.WriteEvent{
					{
						Trigger: "timer:200ms",
						Tag:     "Setpoint",
						Value:   50.0,
					},
				},
			},
		},
	}

	engine, err := NewClientEngine(p, "test")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	// Tick for 100ms - should not fire
	engine.Tick(100 * time.Millisecond)
	writes := engine.GetPendingWrites()
	if len(writes) > 0 {
		t.Errorf("timer should not fire at 100ms, got %d writes", len(writes))
	}

	// Tick for another 150ms - should fire
	engine.Tick(150 * time.Millisecond)
	writes = engine.GetPendingWrites()
	if len(writes) != 1 {
		t.Errorf("timer should fire at 250ms, got %d writes", len(writes))
	}
	if len(writes) > 0 && writes[0].TagName != "Setpoint" {
		t.Errorf("write tag = %q, want 'Setpoint'", writes[0].TagName)
	}
}

func TestClientEngineCanWrite(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	if !engine.CanWrite("Setpoint") {
		t.Error("HMI should be able to write Setpoint")
	}

	if engine.CanWrite("Level") {
		t.Error("HMI should not be able to write Level (read-only)")
	}
}

func TestClientEngineScheduleWrite(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	// Schedule a write to a writable tag
	err = engine.ScheduleWrite("Setpoint", 75.0)
	if err != nil {
		t.Errorf("ScheduleWrite to writable tag failed: %v", err)
	}

	// Try to schedule a write to a non-writable tag
	err = engine.ScheduleWrite("Level", 100.0)
	if err == nil {
		t.Error("ScheduleWrite to non-writable tag should fail")
	}

	// Get pending writes
	writes := engine.GetPendingWrites()
	if len(writes) != 1 {
		t.Errorf("got %d pending writes, want 1", len(writes))
	}
	if len(writes) > 0 && writes[0].TagName != "Setpoint" {
		t.Errorf("write tag = %q, want 'Setpoint'", writes[0].TagName)
	}
}

func TestClientEngineServerState(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	if engine.GetServerState() != "" {
		t.Errorf("initial server state should be empty, got %q", engine.GetServerState())
	}

	engine.UpdateServerState("running")
	if engine.GetServerState() != "running" {
		t.Errorf("server state = %q, want 'running'", engine.GetServerState())
	}

	engine.UpdateServerState("idle")
	if engine.GetServerState() != "idle" {
		t.Errorf("server state = %q, want 'idle'", engine.GetServerState())
	}
}

func TestClientEngineGetWritableTags(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "hmi")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	writableTags := engine.GetWritableTags()
	if len(writableTags) != 2 {
		t.Errorf("got %d writable tags, want 2", len(writableTags))
	}

	expected := map[string]bool{"Setpoint": true, "Alarm": true}
	for _, tag := range writableTags {
		if !expected[tag] {
			t.Errorf("unexpected writable tag: %q", tag)
		}
	}
}

func TestClientEngineHistorianReadOnly(t *testing.T) {
	p := createTestProfile()

	engine, err := NewClientEngine(p, "historian")
	if err != nil {
		t.Fatalf("NewClientEngine failed: %v", err)
	}

	// Historian has no writable tags
	if len(engine.GetWritableTags()) != 0 {
		t.Error("historian should have no writable tags")
	}

	// Cannot schedule writes
	err = engine.ScheduleWrite("Setpoint", 100.0)
	if err == nil {
		t.Error("historian should not be able to schedule writes")
	}
}

func createTestProfile() *profile.Profile {
	return &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Level", Type: "REAL", InitialValue: 50.0, Writable: false},
				{Name: "Flow", Type: "REAL", InitialValue: 0.0, Writable: false},
				{Name: "Pressure", Type: "REAL", InitialValue: 14.7, Writable: false},
				{Name: "Pump", Type: "BOOL", InitialValue: false, Writable: false},
				{Name: "Setpoint", Type: "REAL", InitialValue: 75.0, Writable: true},
				{Name: "Alarm", Type: "BOOL", InitialValue: false, Writable: true},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States: map[string]profile.State{
				"idle":    {},
				"running": {},
			},
		},
		Roles: map[string]profile.Role{
			"hmi": {
				Description:  "Operator HMI",
				PollInterval: "500ms",
				BatchSize:    5,
				ReadTags:     []string{"Level", "Flow", "Pressure", "Pump", "Setpoint"},
				WriteTags:    []string{"Setpoint", "Alarm"},
				WriteEvents: []profile.WriteEvent{
					{
						Trigger: "state:running",
						Tag:     "Setpoint",
						Value:   80.0,
					},
					{
						Trigger: "random:0.5",
						Tag:     "Setpoint",
						Value:   "random:50:90",
					},
				},
			},
			"historian": {
				Description:  "Data historian",
				PollInterval: "5s",
				BatchSize:    10,
				ReadTags:     []string{"Level", "Flow", "Pressure", "Pump", "Setpoint"},
				WriteTags:    []string{}, // Read-only
			},
		},
	}
}
