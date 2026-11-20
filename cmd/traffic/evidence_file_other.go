//go:build !linux

package main

// Other platforms do not charge file cache to the collector's resource limit.
func (f *evidenceFile) releaseWritten(bool) error {
	f.disabled = true
	return nil
}
