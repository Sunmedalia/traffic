package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestRecorderBoundaryOnlyTouchesExactGeneration(t *testing.T) {
	dir := t.TempDir()
	recorder := newRecorder(&Store{dir: dir})
	for _, name := range []string{"ecapture-1/a", "ecapture-1/b", "ecapture-10/a"} {
		if err := recorder.record(name, "ecapture", session.Target{ID: name}, session.RawEvent{Type: "data"}); err != nil {
			t.Fatal(err)
		}
	}
	boundary := session.RawEvent{Type: "loss", Reason: "receive_queue_shed", Unit: "messages", Count: 3}
	if err := recorder.boundary("ecapture-1", boundary); err != nil {
		t.Fatal(err)
	}
	if err := recorder.boundary("ecapture-1", session.RawEvent{Type: "end"}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(dir, "tls", "stream.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := session.NewJSONLines(file, 4096)
	ends, losses, count := 0, 0, uint64(0)
	for {
		var event session.RawEvent
		err := lines.Next(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Type != "end" && event.Type != "loss" {
			continue
		}
		if event.Source == "ecapture-10/a" {
			t.Fatalf("received another generation's boundary: %+v", event)
		}
		if event.Type == "end" {
			ends++
		} else {
			losses++
			count += event.Count
			if event.Unit != boundary.Unit || event.Reason != boundary.Reason {
				t.Fatalf("lost diagnostic attribution: %+v", event)
			}
		}
	}
	if ends != 2 || losses != 2 || count != boundary.Count {
		t.Fatalf("got %d end markers, %d loss markers, %d discarded messages", ends, losses, count)
	}
}
