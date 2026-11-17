package session

import "time"

// RawEvent is an append-only record of bytes/API events at the probe boundary.
// Source identifies one attach generation. A source record supplies its target;
// later records reference Source rather than repeating process metadata.
type RawEvent struct {
	Version    int       `json:"version"`
	Time       time.Time `json:"time"`
	Source     string    `json:"source"`
	Backend    string    `json:"backend,omitempty"`
	Type       string    `json:"type"`
	Target     *Target   `json:"target,omitempty"`
	Connection string    `json:"connection,omitempty"`
	Direction  string    `json:"direction,omitempty"`
	Local      string    `json:"local,omitempty"`
	Client     string    `json:"client,omitempty"`
	Data       []byte    `json:"data,omitempty"`
	Incomplete bool      `json:"incomplete,omitempty"`
	Count      uint64    `json:"count,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	IIS        *IISEvent `json:"iis,omitempty"`
}

type OpenSSLEvent struct {
	Sequence   uint64 `json:"sequence,omitempty"`
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	Message    string `json:"message"`
	Connection string `json:"connection"`
	Direction  string `json:"direction"`
	Local      string `json:"local"`
	Client     string `json:"client"`
	Data       []byte `json:"data_b64"`
	Incomplete bool   `json:"incomplete"`
	Count      uint64 `json:"count"`
}

type IISEvent struct {
	HTTPVersion string      `json:"http_version,omitempty"`
	Protocol    string      `json:"protocol"`
	Type        string      `json:"type"`
	ID          string      `json:"id"`
	Connection  string      `json:"connection"`
	Time        time.Time   `json:"time"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Headers     [][2]string `json:"headers"`
	Client      string      `json:"client"`
	Local       string      `json:"local"`
	Status      int         `json:"status"`
	Data        []byte      `json:"data_b64"`
	Count       uint64      `json:"count"`
	Length      int64       `json:"length"`
	Reason      string      `json:"reason"`
}
