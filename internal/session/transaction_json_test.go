package session

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

func unmarshalTransaction(data []byte) (Transaction, error) {
	var t Transaction
	err := json.Unmarshal(data, &t)
	return t, err
}

func checkDecodeTransaction(t *testing.T, data []byte) {
	t.Helper()
	got, gotErr := DecodeTransaction(data)
	want, wantErr := unmarshalTransaction(data)
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
		t.Fatalf("%q: error %v, want %v", data, gotErr, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q:\ngot  %+v\nwant %+v", data, got, want)
	}
}

func sampleTransactions() [][]byte {
	r := rand.New(rand.NewSource(3))
	body := func() []byte {
		switch r.Intn(5) {
		case 0:
			return nil
		case 1:
			return []byte{}
		}
		b := make([]byte, r.Intn(3000))
		r.Read(b)
		return b
	}
	var out [][]byte
	for i := range 200 {
		t := Transaction{
			ID: fmt.Sprintf("id-%d", i), Time: time.Unix(1700000000, int64(i)).UTC(), Client: "192.0.2.1:80",
			Method: "GET", URL: `/a?q="request":"x"&b=\u00e9`, Host: "demo", Status: 200 + i%3,
			Request: body(), Response: body(), Incomplete: i%2 == 0, IntegrityReasons: []string{"tcp_stream_gap"},
		}
		if i%7 == 0 {
			t.RequestTrailers = map[string][]string{"request": {"x"}, "Response": {"y"}}
		}
		if i%11 == 0 {
			t.Alerts = []Alert{{Rule: "R", Field: "request", Match: `"response":"`}}
		}
		data, _ := json.Marshal(t)
		out = append(out, data)
	}
	return out
}

func TestDecodeTransactionMatchesUnmarshal(t *testing.T) {
	samples := sampleTransactions()
	fast := 0
	for _, data := range samples {
		checkDecodeTransaction(t, data)
		if _, ok := decodeTransactionFast(data); ok {
			fast++
		}
	}
	// Records written by this program must take the fast path.
	if fast < len(samples)*3/4 {
		t.Fatalf("fast path used for %d of %d records", fast, len(samples))
	}
	base := string(samples[1])
	edits := []string{
		// Key spellings encoding/json also matches, and repeated keys.
		strings.Replace(base, `"request":`, `"Request":`, 1),
		strings.Replace(base, `"request":`, `"REQUEST":`, 1),
		strings.Replace(base, `"response":`, `"re\u0073ponse":`, 1),
		strings.Replace(base, `"request":`, `"reque\u017ft":`, 1),
		strings.Replace(base, `"request":`, "\"reque\u017ft\":", 1),
		strings.Replace(base, `"url":`, `"request":"QQ==","url":`, 1),
		strings.Replace(base, `"url":`, `"Request":null,"url":`, 1),
		base[:len(base)-1] + `,"request":null}`,
		base[:len(base)-1] + `,"REQUEST":"QkI="}`,
		// Null, other types and invalid base64 values.
		strings.Replace(base, `"request":"`, `"request":null,"x":"`, 1),
		strings.Replace(base, `"request":"`, `"request":"!!`, 1),
		strings.Replace(base, `"request":"`, `"request":"Q\nQ==`, 1),
		strings.Replace(base, `"request":"`, `"request":"Q\r`, 1),
		strings.Replace(base, `"request":"`, `"request":"\u0051`, 1),
		strings.Replace(base, `"request":"`, `"request":"QQ=`, 1),
		// Structure around the member.
		strings.Replace(base, `,"request":`, ` ,"request":`, 1),
		strings.Replace(base, `,"request":`, `, "request":`, 1),
		strings.Replace(base, `"request":`, `"request" :`, 1),
		strings.Replace(base, `,"request":`, `"request":`, 1),
		strings.Replace(base, `,"response":`, `,,"response":`, 1),
		strings.Replace(base, `,"response":`, `"response":`, 1),
		base + `x`,
		base + ` `,
		base[:len(base)-1],
		" " + base,
		`[` + base + `]`,
		// Nested members named like the bodies.
		strings.Replace(base, `"url":`, `"extra":{"request":"QQ=="},"url":`, 1),
		strings.Replace(base, `"url":`, `"extra":[{"response":"QQ=="}],"url":`, 1),
		strings.Replace(base, `"url":`, `"alerts":[{"rule":"R","request":"QQ=="}],"url":`, 1),
		// Type errors elsewhere still fill the rest of the record.
		strings.Replace(base, `"status":`, `"status":"x","s":`, 1),
		`{"request":"QQ=="}`, `{"response":"QQ==","request":""}`, `{"request":"QQ==","response":"Qg=="}`,
		`{"request":"QQ==",}`, `{"request":"QQ==", "id":"x"}`, `{,"request":"QQ=="}`, `{ ,"request":"QQ=="}`, `{"id":"x" ,"request":"QQ=="}`,
		`{"id":,"request":"QQ=="}`, `{"id":1,"request":"QQ=="}`, `{"incomplete":true,"request":"QQ=="}`, `{"pid":null,"request":"QQ=="}`,
		`{"request":"QQ==","response":"Qg==",}`, `{"request":"QQ==",,"response":"Qg=="}`, `{"response":"Qg==","request":"QQ=="}`, `{"request":"QQ=="`, `{"request":"QQ==`, `{"request`,
		`{}`, `null`, ``, `{"id":"\"","request":"QQ=="}`, `{"id":"\\","request":"QQ=="}`,
	}
	for _, edit := range edits {
		checkDecodeTransaction(t, []byte(edit))
	}
}

func FuzzDecodeTransaction(f *testing.F) {
	for _, data := range sampleTransactions()[:20] {
		f.Add(data)
	}
	f.Add([]byte(`{"request":"QQ==","response":"Qg==","url":"/"}`))
	f.Add([]byte(`{"Request":"QQ==","request":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		checkDecodeTransaction(t, data)
	})
}

func BenchmarkDecodeTransaction(b *testing.B) {
	samples := sampleTransactions()
	for _, mode := range []struct {
		name   string
		decode func([]byte) (Transaction, error)
	}{{"fast", DecodeTransaction}, {"unmarshal", unmarshalTransaction}} {
		b.Run(mode.name, func(b *testing.B) {
			for b.Loop() {
				for _, data := range samples {
					mode.decode(data)
				}
			}
		})
	}
}
