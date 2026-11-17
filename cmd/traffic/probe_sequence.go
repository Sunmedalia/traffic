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
