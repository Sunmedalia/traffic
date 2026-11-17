package main

import (
	"fmt"
	"testing"
)

func TestProtobufMalformed(t *testing.T) {
	for _, b := range [][]byte{{255}, {10, 255}, {8, 255}} {
		if _, _, e := protoFields(b); e == nil {
			t.Fatal(fmt.Sprint(b))
		}
	}
}

func TestDropCountersAcrossInterfaces(t *testing.T) {
	s := &Store{}
	s.recordPacketDrops("eth0", 3)
	s.recordPacketDrops("lo", 4)
	s.recordPacketDrops("eth0", 5)
	if s.stats.Dropped != 9 {
		t.Fatalf("lost interface count: %d", s.stats.Dropped)
	}
}
