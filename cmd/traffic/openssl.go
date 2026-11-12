package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type opensslEvent struct {
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

type opensslAssembler struct {
	processor  *HTTPProcessor
	frames     *Frames
	prefix     string
	pid        int
	generation uint64
	uncertain  bool
}

// Clear request/response correlation at a known stream boundary. Persist requests
// that never received a complete response rather than pairing them with later I/O.
func (a *opensslAssembler) close(connection string) error {
	p := a.processor
	a.frames.expire(time.Now(), true, p, connection)
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, queue := range p.pending {
		if (connection != "" && key != "tls:"+connection) || !strings.HasPrefix(key, "tls:"+a.prefix) {
			continue
		}
		for _, record := range queue {
			if err := p.s.restore(&record); err != nil {
				return err
			}
			record.Incomplete = true
			if err := p.s.save(record); err != nil {
				return err
			}
		}
		delete(p.pending, key)
	}
	for key := range p.requestMethods {
		if (connection == "" || key == "tls:"+connection) && strings.HasPrefix(key, "tls:"+a.prefix) {
			delete(p.requestMethods, key)
		}
	}
	for key, queue := range p.responses {
		if (connection != "" && key != "tls:"+connection) || !strings.HasPrefix(key, "tls:"+a.prefix) {
			continue
		}
		for _, response := range queue {
			p.responseBytes -= int64(len(response.raw))
			p.responseCount--
		}
		delete(p.responses, key)
	}
	return nil
}

func (a *opensslAssembler) ingest(event opensslEvent) error {
	p := a.processor
	connection := fmt.Sprintf("%s%d/%s", a.prefix, a.generation, event.Connection)
	switch event.Type {
	case "loss":
		p.s.mu.Lock()
		p.s.stats.TLSDropped += event.Count
		p.s.mu.Unlock()
		if err := a.close(""); err != nil {
			return err
		}
		a.generation++
		// Host queue loss cannot be attributed to an individual connection.
		a.uncertain = true
	case "close":
		return a.close(connection)
	case "data":
		if event.Direction != "read" && event.Direction != "write" {
			return fmt.Errorf("invalid OpenSSL event direction")
		}
		if event.Connection == "" || len(event.Data) == 0 {
			return fmt.Errorf("invalid OpenSSL connection event")
		}
		_, localText, err := net.SplitHostPort(event.Local)
		if err != nil {
			return fmt.Errorf("invalid OpenSSL local endpoint: %w", err)
		}
		_, remoteText, err := net.SplitHostPort(event.Client)
		if err != nil {
			return fmt.Errorf("invalid OpenSSL peer endpoint: %w", err)
		}
		localPort, _ := strconv.Atoi(localText)
		remotePort, _ := strconv.Atoi(remoteText)
		if !capturePorts[localPort] && !capturePorts[remotePort] {
			return nil
		}
		p.mu.Lock()
		queue := p.pending["tls:"+connection]
		head := len(queue) > 0 && queue[0].Method == "HEAD"
		p.mu.Unlock()
		// A response observed while attaching to an in-flight request must not be
		// retained and assigned to the next request on this keepalive connection.
		responseDirection := "read"
		if capturePorts[localPort] {
			responseDirection = "write"
		}
		if len(queue) == 0 && event.Direction == responseDirection {
			return nil
		}
		a.frames.ingest(connection+event.Direction, event.Data, frameContext{connection: connection, client: event.Client, local: event.Local, pid: a.pid, incomplete: event.Incomplete || a.uncertain}, head, p)
	}
	return nil
}
