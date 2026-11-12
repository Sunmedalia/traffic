package session

import "time"

type Target struct {
	GID     int    `json:"gid"`
	Ports   []int  `json:"ports,omitempty"`
	ID      string `json:"id"`
	PID     int    `json:"pid"`
	UID     int    `json:"uid"`
	Service string `json:"service"`
	Library string `json:"library,omitempty"`
	State   string `json:"state"`
}

type Transaction struct {
	Backend       string    `json:"backend,omitempty"`
	LocalEndpoint string    `json:"local_endpoint,omitempty"`
	Service       string    `json:"service,omitempty"`
	TargetID      string    `json:"target_id,omitempty"`
	Host          string    `json:"host,omitempty"`
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	Source        string    `json:"source"`
	Client        string    `json:"client"`
	Connection    string    `json:"connection"`
	Method        string    `json:"method"`
	URL           string    `json:"url"`
	Request       []byte    `json:"request,omitempty"`
	Response      []byte    `json:"response,omitempty"`
	Status        int       `json:"status"`
	Incomplete    bool      `json:"incomplete"`
	Truncated     bool      `json:"truncated"`
	PID           int       `json:"pid,omitempty"`
	Alerts        []Alert   `json:"alerts,omitempty"`
}
type Alert struct {
	View     string `json:"view,omitempty"`
	Version  int    `json:"version"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Match    string `json:"match"`
	Decoding int    `json:"decoding"`
}
type Stats struct {
	Targets        []Target  `json:"targets,omitempty"`
	ResourceLimits string    `json:"resource_limits"`
	TLSDropped     uint64    `json:"tls_dropped"`
	QueueDropped   uint64    `json:"queue_dropped"`
	Started        time.Time `json:"started"`
	State          string    `json:"state"`
	Packets        uint64    `json:"packets"`
	Transactions   uint64    `json:"transactions"`
	Alerts         uint64    `json:"alerts"`
	Dropped        uint64    `json:"dropped"`
	TLS            string    `json:"tls"`
	Errors         []string  `json:"errors,omitempty"`
}

const IndexTimeFormat = "2006-01-02T15:04:05.000000000Z"
