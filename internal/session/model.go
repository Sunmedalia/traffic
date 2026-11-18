package session

import "time"

type Target struct {
	DiscoveredAt time.Time `json:"discovered_at,omitempty"`
	StartingAt   time.Time `json:"starting_at,omitempty"`
	ReadyAt      time.Time `json:"ready_at,omitempty"`
	GID          int       `json:"gid"`
	Ports        []int     `json:"ports,omitempty"`
	ID           string    `json:"id"`
	PID          int       `json:"pid"`
	UID          int       `json:"uid"`
	Service      string    `json:"service"`
	Library      string    `json:"library,omitempty"`
	State        string    `json:"state"`
}

type GapEvent struct {
	Time       time.Time `json:"time"`
	Backend    string    `json:"backend"`
	Connection string    `json:"connection,omitempty"`
	Reason     string    `json:"reason"`
	Count      uint64    `json:"count"`
	Unit       string    `json:"unit"`
}

type Transaction struct {
	RequestTrailers  map[string][]string `json:"request_trailers,omitempty"`
	ResponseTrailers map[string][]string `json:"response_trailers,omitempty"`
	Protocol         string              `json:"protocol,omitempty"`
	StreamID         uint32              `json:"stream_id,omitempty"`
	Generation       uint64              `json:"generation,omitempty"`
	IntegrityReasons []string            `json:"integrity_reasons,omitempty"`
	Backend          string              `json:"backend,omitempty"`
	LocalEndpoint    string              `json:"local_endpoint,omitempty"`
	Service          string              `json:"service,omitempty"`
	TargetID         string              `json:"target_id,omitempty"`
	Host             string              `json:"host,omitempty"`
	SchemaVersion    int                 `json:"schema_version"`
	ID               string              `json:"id"`
	Time             time.Time           `json:"time"`
	Source           string              `json:"source"`
	Client           string              `json:"client"`
	PeerClient       string              `json:"peer_client,omitempty"`
	ClientSource     string              `json:"client_source,omitempty"`
	Connection       string              `json:"connection"`
	Method           string              `json:"method"`
	URL              string              `json:"url"`
	Request          []byte              `json:"request,omitempty"`
	Response         []byte              `json:"response,omitempty"`
	Status           int                 `json:"status"`
	Incomplete       bool                `json:"incomplete"`
	Truncated        bool                `json:"truncated"`
	PID              int                 `json:"pid,omitempty"`
	Alerts           []Alert             `json:"alerts,omitempty"`
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
type ProbeExit struct {
	HookBased         bool   `json:"hook_based,omitempty"`
	DataDrained       bool   `json:"data_drained"`
	HooksRemoved      bool   `json:"hooks_removed"`
	ScriptUnloaded    bool   `json:"script_unloaded"`
	TransportDetached bool   `json:"transport_detached"`
	RuntimeState      string `json:"runtime_state,omitempty"`
}

// ProbeTransportStats measures socket acceptance and dequeueing, not requests
// captured or persisted. Cumulative failures survive a successful reattach.
type ProbeTransportStats struct {
	Generation       uint64 `json:"generation"`
	ReceivedMessages uint64 `json:"received_messages"`
	ReceivedBytes    uint64 `json:"received_bytes"`
	DequeuedMessages uint64 `json:"dequeued_messages"`
	DequeuedBytes    uint64 `json:"dequeued_bytes"`
	PendingBytes     int64  `json:"pending_bytes"`
	QueuedMessages   int    `json:"queued_messages"`
	HighWaterBytes   int64  `json:"high_water_bytes"`
	Overflows        uint64 `json:"overflows"`
	// Shed counters report messages discarded while the receive queue was
	// over budget. The transport keeps running and marks a loss boundary.
	ShedMessages uint64 `json:"shed_messages,omitempty"`
	ShedBytes    uint64 `json:"shed_bytes,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	Ended        bool   `json:"ended"`
}

type Stats struct {
	ProbeTransports             map[string]ProbeTransportStats `json:"probe_transports,omitempty"`
	ProbeFailures               uint64                         `json:"probe_failures,omitempty"`
	PacketInterfaces            map[string]string              `json:"packet_interfaces,omitempty"`
	DiagnosticsVersion          int                            `json:"diagnostics_version,omitempty"`
	RawEvidencePendingBytes     uint64                         `json:"raw_evidence_pending_bytes,omitempty"`
	RawEvidenceHighWaterBytes   uint64                         `json:"raw_evidence_high_water_bytes,omitempty"`
	RawEvidenceWriters          uint64                         `json:"raw_evidence_writers,omitempty"`
	RawEvidenceDrainUnconfirmed bool                           `json:"raw_evidence_drain_unconfirmed,omitempty"`
	IndexPendingWrites          uint64                         `json:"index_pending_writes,omitempty"`
	ProbeExits                  map[string]ProbeExit           `json:"probe_exits,omitempty"`
	GapCounts                   map[string]uint64              `json:"gap_counts,omitempty"`
	GapJournalSuppressed        uint64                         `json:"gap_journal_suppressed,omitempty"`
	DrainState                  string                         `json:"drain_state,omitempty"`
	StopReason                  string                         `json:"stop_reason,omitempty"`
	AlertDelivered              uint64                         `json:"alert_delivered"`
	AlertDeliveryFailed         uint64                         `json:"alert_delivery_failed"`
	AlertDeliveryDropped        uint64                         `json:"alert_delivery_dropped"`
	TLSWireRecords              uint64                         `json:"tls_wire_records"`
	TLSRequests                 uint64                         `json:"tls_requests"`
	TLSCoverage                 string                         `json:"tls_coverage,omitempty"`
	PlaintextObserved           bool                           `json:"plaintext_observed"`
	AttachWindowSuspect         bool                           `json:"attach_window_suspect"`
	ProbeReceiveMatches         uint64                         `json:"probe_receive_matches"`
	ProbeRecoveredReceives      uint64                         `json:"probe_recovered_receives"`
	ProbeBodyMatches            uint64                         `json:"probe_body_matches"`
	ProbeSendMatches            uint64                         `json:"probe_send_matches"`
	ProbeUnmatchedCompletions   uint64                         `json:"probe_unmatched_completions"`
	TLSMissingEstimate          *uint64                        `json:"tls_missing_estimate"`
	Targets                     []Target                       `json:"targets,omitempty"`
	ResourceLimits              string                         `json:"resource_limits"`
	TLSDropped                  uint64                         `json:"tls_dropped"`
	QueueDropped                uint64                         `json:"queue_dropped"`
	Started                     time.Time                      `json:"started"`
	Stopped                     time.Time                      `json:"stopped,omitempty"`
	FirstPacketAt               time.Time                      `json:"first_packet_at,omitempty"`
	LastPacketAt                time.Time                      `json:"last_packet_at,omitempty"`
	LastPacketPollAt            time.Time                      `json:"last_packet_poll_at,omitempty"`
	LastTLSEventAt              time.Time                      `json:"last_tls_event_at,omitempty"`
	IntegrityWarnings           []string                       `json:"integrity_warnings,omitempty"`
	State                       string                         `json:"state"`
	Packets                     uint64                         `json:"packets"`
	Transactions                uint64                         `json:"transactions"`
	Alerts                      uint64                         `json:"alerts"`
	Dropped                     uint64                         `json:"dropped"`
	TLS                         string                         `json:"tls"`
	Errors                      []string                       `json:"errors,omitempty"`
}

const IndexTimeFormat = "2006-01-02T15:04:05.000000000Z"
