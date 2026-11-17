package main

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestProtobufMalformed(t *testing.T) {
	for _, b := range [][]byte{{255}, {10, 255}, {8, 255}} {
		var m protoFields
		if e := m.parse(b); e == nil {
			t.Fatal(fmt.Sprint(b))
		}
	}
}

func TestProtobufFixedFields(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 17, protowire.VarintType)
	b = protowire.AppendVarint(b, 42)
	b = protowire.AppendTag(b, 11, protowire.BytesType)
	b = protowire.AppendBytes(b, []byte("payload"))
	b = protowire.AppendTag(b, 900, protowire.BytesType)
	b = protowire.AppendBytes(b, []byte("ignored"))
	var m protoFields
	if err := m.parse(b); err != nil || m.ints[17] != 42 || string(m.bytes[11]) != "payload" {
		t.Fatal("fixed field parse", err, m.ints[17], string(m.bytes[11]))
	}
	if err := m.parse(nil); err != nil || m.ints[17] != 0 || m.bytes[11] != nil {
		t.Fatal("parse did not reset previous fields")
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
