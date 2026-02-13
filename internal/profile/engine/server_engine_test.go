package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/profile"
)

func TestNewServerEngine(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Counter", Type: "DINT", InitialValue: 0, UpdateRule: "counter", UpdateParams: map[string]interface{}{"increment": 1, "interval": "1s"}},
				{Name: "Level", Type: "REAL", InitialValue: 50.0, UpdateRule: "ramp", UpdateParams: map[string]interface{}{"min": 0.0, "max": 100.0, "rate": 10.0}},
				{Name: "Flag", Type: "BOOL", InitialValue: false, Writable: true, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States: map[string]profile.State{
				"idle": {
					Description: "Idle state",
					Transitions: []profile.Transition{
						{To: "running", Condition: "tag:Flag==true"},
					},
				},
				"running": {
					Description: "Running state",
					Transitions: []profile.Transition{
						{To: "idle", Condition: "timer:5s"},
					},
				},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	if engine.CurrentState() != "idle" {
		t.Errorf("initial state = %q, want 'idle'", engine.CurrentState())
	}

	// Check initial tag values
	if v, ok := engine.GetTagValue("Counter"); !ok || v != 0 {
		t.Errorf("Counter initial = %v, want 0", v)
	}
	if v, ok := engine.GetTagValue("Level"); !ok || v != 50.0 {
		t.Errorf("Level initial = %v, want 50.0", v)
	}
	if v, ok := engine.GetTagValue("Flag"); !ok || v != false {
		t.Errorf("Flag initial = %v, want false", v)
	}
}

func TestServerEngineTick(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Counter", Type: "DINT", InitialValue: 0, UpdateRule: "counter", UpdateParams: map[string]interface{}{"increment": float64(1), "interval": "100ms"}},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States: map[string]profile.State{
				"idle": {},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Tick for 500ms - should increment counter 5 times
	for i := 0; i < 5; i++ {
		if err := engine.Tick(100 * time.Millisecond); err != nil {
			t.Fatalf("Tick failed: %v", err)
		}
	}

	v, ok := engine.GetTagValue("Counter")
	if !ok {
		t.Fatal("Counter not found")
	}

	// Counter should have incremented 5 times
	count := toInt(v)
	if count != 5 {
		t.Errorf("Counter = %d, want 5", count)
	}
}

func TestServerEngineTransition(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Trigger", Type: "BOOL", InitialValue: false, Writable: true, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States: map[string]profile.State{
				"idle": {
					Transitions: []profile.Transition{
						{To: "running", Condition: "tag:Trigger==true"},
					},
				},
				"running": {
					Transitions: []profile.Transition{
						{To: "idle", Condition: "tag:Trigger==false"},
					},
				},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Should start in idle
	if engine.CurrentState() != "idle" {
		t.Errorf("state = %q, want 'idle'", engine.CurrentState())
	}

	// Set trigger to true
	accepted, err := engine.ApplyWrite("Trigger", []byte{1})
	if err != nil || !accepted {
		t.Fatalf("ApplyWrite failed: accepted=%v, err=%v", accepted, err)
	}

	// Tick should transition to running
	engine.Tick(100 * time.Millisecond)

	if engine.CurrentState() != "running" {
		t.Errorf("state = %q, want 'running'", engine.CurrentState())
	}

	// Set trigger to false
	engine.ApplyWrite("Trigger", []byte{0})
	engine.Tick(100 * time.Millisecond)

	if engine.CurrentState() != "idle" {
		t.Errorf("state = %q, want 'idle'", engine.CurrentState())
	}
}

func TestServerEngineTimerTransition(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Dummy", Type: "BOOL", InitialValue: false, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "state1",
			States: map[string]profile.State{
				"state1": {
					Transitions: []profile.Transition{
						{To: "state2", Condition: "timer:200ms"},
					},
				},
				"state2": {},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Tick for 100ms - should still be in state1
	engine.Tick(100 * time.Millisecond)
	if engine.CurrentState() != "state1" {
		t.Errorf("after 100ms: state = %q, want 'state1'", engine.CurrentState())
	}

	// Tick for another 150ms - should transition to state2
	engine.Tick(150 * time.Millisecond)
	if engine.CurrentState() != "state2" {
		t.Errorf("after 250ms: state = %q, want 'state2'", engine.CurrentState())
	}
}

func TestServerEngineStateOverrides(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Value", Type: "DINT", InitialValue: 0, UpdateRule: "static"},
				{Name: "Trigger", Type: "BOOL", InitialValue: false, Writable: true, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "state1",
			States: map[string]profile.State{
				"state1": {
					TagOverrides: map[string]string{
						"Value": "static:100",
					},
					Transitions: []profile.Transition{
						{To: "state2", Condition: "tag:Trigger==true"},
					},
				},
				"state2": {
					TagOverrides: map[string]string{
						"Value": "static:200",
					},
				},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Value should be 100 in state1
	v, _ := engine.GetTagValue("Value")
	if toInt(v) != 100 {
		t.Errorf("Value in state1 = %v, want 100", v)
	}

	// Transition to state2
	engine.ApplyWrite("Trigger", []byte{1})
	engine.Tick(100 * time.Millisecond)

	// Value should be 200 in state2
	v, _ = engine.GetTagValue("Value")
	if toInt(v) != 200 {
		t.Errorf("Value in state2 = %v, want 200", v)
	}
}

func TestServerEngineResolveRead(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "IntVal", Type: "DINT", InitialValue: 12345, UpdateRule: "static"},
				{Name: "RealVal", Type: "REAL", InitialValue: 3.14, UpdateRule: "static"},
				{Name: "BoolVal", Type: "BOOL", InitialValue: true, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States:       map[string]profile.State{"idle": {}},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Read DINT
	data, err := engine.ResolveRead("IntVal")
	if err != nil {
		t.Fatalf("ResolveRead(IntVal) failed: %v", err)
	}
	if len(data) != 4 {
		t.Errorf("IntVal length = %d, want 4", len(data))
	}

	// Read REAL
	data, err = engine.ResolveRead("RealVal")
	if err != nil {
		t.Fatalf("ResolveRead(RealVal) failed: %v", err)
	}
	if len(data) != 4 {
		t.Errorf("RealVal length = %d, want 4", len(data))
	}

	// Read BOOL
	data, err = engine.ResolveRead("BoolVal")
	if err != nil {
		t.Fatalf("ResolveRead(BoolVal) failed: %v", err)
	}
	if len(data) != 1 || data[0] != 1 {
		t.Errorf("BoolVal = %v, want [1]", data)
	}

	// Read unknown
	_, err = engine.ResolveRead("Unknown")
	if err == nil {
		t.Error("ResolveRead(Unknown) should fail")
	}
}

func TestServerEngineApplyWrite(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Writable", Type: "DINT", InitialValue: 0, Writable: true, UpdateRule: "static"},
				{Name: "ReadOnly", Type: "DINT", InitialValue: 0, Writable: false, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States:       map[string]profile.State{"idle": {}},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Write to writable tag
	accepted, err := engine.ApplyWrite("Writable", []byte{0x39, 0x30, 0x00, 0x00}) // 12345
	if err != nil || !accepted {
		t.Errorf("write to Writable: accepted=%v, err=%v", accepted, err)
	}

	// Write to read-only tag
	accepted, err = engine.ApplyWrite("ReadOnly", []byte{0x01, 0x00, 0x00, 0x00})
	if err != nil || accepted {
		t.Errorf("write to ReadOnly should be denied: accepted=%v, err=%v", accepted, err)
	}

	// Write to unknown tag
	_, err = engine.ApplyWrite("Unknown", []byte{0x01})
	if err == nil {
		t.Error("write to Unknown should fail")
	}
}

func TestServerEngineEvents(t *testing.T) {
	p := &profile.Profile{
		Metadata: profile.Metadata{
			Name:        "Test Profile",
			Personality: "logix_like",
			Seed:        12345,
		},
		DataModel: profile.DataModel{
			Tags: []profile.TagDefinition{
				{Name: "Counter", Type: "DINT", InitialValue: 0, UpdateRule: "static"},
			},
		},
		StateMachine: profile.StateMachine{
			InitialState: "idle",
			States: map[string]profile.State{
				"idle": {
					Events: []profile.Event{
						{
							Name:    "test_event",
							Trigger: "timer:100ms",
							Actions: []profile.Action{
								{Type: "log", Value: "Event triggered"},
							},
						},
					},
				},
			},
		},
		Roles: map[string]profile.Role{},
	}

	engine, err := NewServerEngine(p)
	if err != nil {
		t.Fatalf("NewServerEngine failed: %v", err)
	}

	// Tick past trigger time
	engine.Tick(150 * time.Millisecond)

	// Check event log
	log := engine.GetEventLog()
	found := false
	for _, rec := range log {
		if rec.Event == "test_event" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test_event not found in event log")
	}
}

func TestUpdateRules(t *testing.T) {
	t.Run("counter", func(t *testing.T) {
		rule := ParseUpdateRule("counter", map[string]interface{}{
			"increment": float64(5),
			"interval":  "100ms",
		})

		value := rule.Update(int64(0), 100*time.Millisecond, nil)
		if v := toInt(value); v != 5 {
			t.Errorf("counter after 100ms = %d, want 5", v)
		}

		value = rule.Update(value, 200*time.Millisecond, nil)
		if v := toInt(value); v != 15 {
			t.Errorf("counter after 300ms = %d, want 15", v)
		}
	})

	t.Run("ramp", func(t *testing.T) {
		rule := ParseUpdateRule("ramp", map[string]interface{}{
			"min":  0.0,
			"max":  100.0,
			"rate": 10.0,
		})

		value := float64(50)
		value = rule.Update(value, time.Second, nil).(float64)
		if value != 60.0 {
			t.Errorf("ramp after 1s = %f, want 60.0", value)
		}

		// Ramp to max and bounce
		for i := 0; i < 5; i++ {
			value = rule.Update(value, time.Second, nil).(float64)
		}
		if value >= 100.0 {
			t.Errorf("ramp should bounce at max, got %f", value)
		}
	})

	t.Run("toggle", func(t *testing.T) {
		rule := ParseUpdateRule("toggle", map[string]interface{}{
			"interval": "100ms",
		})

		value := false
		value = rule.Update(value, 100*time.Millisecond, nil).(bool)
		if !value {
			t.Error("toggle should be true after interval")
		}

		value = rule.Update(value, 100*time.Millisecond, nil).(bool)
		if value {
			t.Error("toggle should be false after second interval")
		}
	})
}

func TestConditions(t *testing.T) {
	t.Run("timer", func(t *testing.T) {
		cond := ParseCondition("timer:100ms")
		ctx := &ConditionContext{TimeInState: 50 * time.Millisecond}
		if cond.Evaluate(ctx) {
			t.Error("timer should not trigger at 50ms")
		}

		ctx.TimeInState = 100 * time.Millisecond
		if !cond.Evaluate(ctx) {
			t.Error("timer should trigger at 100ms")
		}
	})

	t.Run("tag equals", func(t *testing.T) {
		cond := ParseCondition("tag:Flag==true")
		ctx := &ConditionContext{
			TagValues: map[string]interface{}{"Flag": false},
		}
		if cond.Evaluate(ctx) {
			t.Error("should not match when Flag=false")
		}

		ctx.TagValues["Flag"] = true
		if !cond.Evaluate(ctx) {
			t.Error("should match when Flag=true")
		}
	})

	t.Run("tag comparison", func(t *testing.T) {
		cond := ParseCondition("tag:Level>50")
		ctx := &ConditionContext{
			TagValues: map[string]interface{}{"Level": 40.0},
		}
		if cond.Evaluate(ctx) {
			t.Error("should not match when Level=40")
		}

		ctx.TagValues["Level"] = 60.0
		if !cond.Evaluate(ctx) {
			t.Error("should match when Level=60")
		}
	})
}
