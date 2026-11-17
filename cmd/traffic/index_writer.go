package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type indexExecutor interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

// Transactions bound write amplification while restore reads the same writer
// transaction. Independent analysts see only committed WAL snapshots.
func (s *Store) indexExecutorLocked() (indexExecutor, error) {
	if !s.indexBatching {
		return s.db, nil
	}
	if s.indexTx == nil {
		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}
		read, err := tx.Prepare("SELECT data FROM requests WHERE id=?")
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		write, err := tx.Prepare("INSERT OR REPLACE INTO requests VALUES(?,?,?,?,?)")
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		exists, err := tx.Prepare("SELECT EXISTS(SELECT 1 FROM requests WHERE id=?)")
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		s.indexExists = exists
		s.indexTx = tx
		s.indexRead, s.indexWrite = read, write
	}
	return s.indexTx, nil
}

// Statements belong to one batch transaction and are closed by Commit/Rollback.
// Restore must read through that same transaction to see uncommitted requests.
func (s *Store) indexReadRowLocked(reader indexExecutor, id string) *sql.Row {
	if s.indexRead != nil {
		return s.indexRead.QueryRow(id)
	}
	return reader.QueryRow("SELECT data FROM requests WHERE id=?", id)
}

func (s *Store) persist(t Transaction) ([]Alert, error) {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	writer, err := s.indexExecutorLocked()
	if err != nil {
		return nil, err
	}
	var exists bool
	if s.indexExists != nil {
		err = s.indexExists.QueryRow(t.ID).Scan(&exists)
	} else {
		err = writer.QueryRow("SELECT EXISTS(SELECT 1 FROM requests WHERE id=?)", t.ID).Scan(&exists)
	}
	if err != nil {
		return nil, err
	}
	fresh := !exists
	t.Alerts = nil
	data, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	args := []any{t.ID, t.Time.UTC().Format(indexTimeFormat), t.Client, len(t.Alerts), data}
	if s.indexWrite != nil {
		_, err = s.indexWrite.Exec(args...)
	} else {
		_, err = writer.Exec("INSERT OR REPLACE INTO requests VALUES(?,?,?,?,?)", args...)
	}
	if err != nil {
		return nil, err
	}
	if s.indexBatching {
		s.indexOps++
		s.indexBytes += len(data)
		s.mu.Lock()
		s.stats.IndexPendingWrites = uint64(s.indexOps)
		s.mu.Unlock()
		if s.indexOps >= 64 || s.indexBytes >= 4<<20 {
			if err := s.flushIndexLocked(); err != nil {
				return nil, err
			}
		}
	}
	s.mu.Lock()
	if fresh {
		s.stats.Transactions++
		if t.Backend != "pcap" && t.Method != "" {
			s.stats.TLSRequests++
		}
	}

	s.mu.Unlock()
	return nil, nil
}
func (s *Store) flushIndexLocked() error {
	if s.indexTx == nil {
		return nil
	}
	tx, ops := s.indexTx, s.indexOps
	s.indexTx = nil
	s.indexRead, s.indexWrite, s.indexExists = nil, nil, nil
	s.indexOps = 0
	s.indexBytes = 0
	err := tx.Commit()
	s.mu.Lock()
	s.stats.IndexPendingWrites = 0
	s.mu.Unlock()
	if err != nil {
		_ = tx.Rollback()
		s.gap("index", "", "commit_unconfirmed", "writes", uint64(ops))
		return fmt.Errorf("commit session index: %w", err)
	}
	return nil
}
func (s *Store) flushIndex() error {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	return s.flushIndexLocked()
}

// Retention shares the writer transaction: the database has a single connection,
// which belongs to indexTx until the batch commits.
func (s *Store) pruneIndex(before time.Time) error {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	var writer indexExecutor = s.db
	if s.indexTx != nil {
		writer = s.indexTx
	}
	_, err := writer.Exec("DELETE FROM requests WHERE time < ?", before.UTC().Format(indexTimeFormat))
	return err
}
func (s *Store) startIndexWriter(ctx context.Context) func() error {
	s.indexMu.Lock()
	s.indexBatching = true
	s.indexMu.Unlock()
	lifetime, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if err := s.flushIndex(); err != nil {
					s.fail(err)
					return
				}
			}
		}
	}()
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			cancel()
			<-done
			s.indexMu.Lock()
			defer s.indexMu.Unlock()
			result = s.flushIndexLocked()
			s.indexBatching = false
		})
		return result
	}
}
