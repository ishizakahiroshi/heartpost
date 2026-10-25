package audit

import (
	"encoding/json"
	"testing"
)

func TestEventWireFields(t *testing.T) {
	body, err := json.Marshal(Event{Time: "example", Event: "LOGIN", User: "operator", Result: "success"})
	if err != nil || string(body) != `{"time":"example","event":"LOGIN","user":"operator","result":"success"}` {
		t.Fatalf("event wire=%s %v", body, err)
	}
}
