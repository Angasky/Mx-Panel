package yaml

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEmitterQueueDoesNotRetainConsumedEvents(t *testing.T) {
	nodes := make([]interface{}, 2000)
	for i := range nodes {
		nodes[i] = map[string]interface{}{"name": fmt.Sprintf("node-%d", i), "config": map[string]interface{}{"server": "example.com", "port": 24443, "password": "true\nsecret"}}
	}
	var output bytes.Buffer
	encoder := NewEncoder(&output)
	for i := 0; i < 3; i++ {
		if err := encoder.Encode(map[string]interface{}{"nodes": nodes, "round": i}); err != nil {
			t.Fatal(err)
		}
		queue := encoder.encoder.emitter
		if cap(queue.events) > 16 || queue.events_head != 0 {
			t.Fatalf("consumed event queue retained: len=%d cap=%d head=%d", len(queue.events), cap(queue.events), queue.events_head)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder(bytes.NewReader(output.Bytes()))
	for i := 0; i < 3; i++ {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["round"] != i || len(doc["nodes"].([]interface{})) != len(nodes) {
			t.Fatal("compaction changed stream data")
		}
	}
}
