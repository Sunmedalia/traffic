package main

// eCapture numbers published events before they enter its output queues. Track
// the complete transport before PID/port filtering: gaps count published probe
// events, not missing HTTP requests or only selected targets.
type probeSequence struct{ last uint64 }

func (s *probeSequence) observe(current uint64) (missing uint64, reset bool) {
	if current == 0 {
		if s.last != 0 {
			s.last = 0
			return 0, true
		}
		return 0, false // Legacy probes provide no sequence confirmation.
	}
	previous := s.last
	s.last = current
	if current <= previous {
		return 0, true
	}
	return current - previous - 1, false
}

// sequenceDiscontinuity describes a nonconsecutive pair. A restart or reorder
// counts as a transition because the number of missing events is unknown.
func sequenceDiscontinuity(previous, current uint64) (reason, unit string, count uint64) {
	if current <= previous {
		return "transport_sequence_reset_or_reorder", "transitions", 1
	}
	return "transport_sequence_gap", "events", current - previous - 1
}
