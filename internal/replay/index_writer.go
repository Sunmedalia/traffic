package replay

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
		insert, err := tx.Prepare(indexInsert)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		update, err := tx.Prepare(indexUpdate)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		s.indexTx = tx
		s.indexRead, s.indexInsert, s.indexUpdate = read, insert, update
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

// A record is normally written once: HTTP/1.1 requests wait in memory for
// their response. The insert reports whether the ID is new, which replaces a
// SELECT EXISTS per write; only a rewrite of a stored ID (a spilled request,
// an IIS or HTTP/2 stream saved again) runs the update as well.
const (
	indexInsert = "INSERT OR IGNORE INTO requests VALUES(?,?,?,?,?)"
	indexUpdate = "UPDATE requests SET time=?,client=?,alert=?,data=? WHERE id=?"
)

func (s *Store) persist(t Transaction) ([]Alert, error) {
	t.Alerts = nil
	// Encoding needs no index state; keep it outside the writer lock.
	data, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	stamp := t.Time.UTC().Format(indexTimeFormat)
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	writer, err := s.indexExecutorLocked()
	if err != nil {
		return nil, err
	}
	var result sql.Result
	if s.indexInsert != nil {
		result, err = s.indexInsert.Exec(t.ID, stamp, t.Client, 0, data)
	} else {
		result, err = writer.Exec(indexInsert, t.ID, stamp, t.Client, 0, data)
	}
	if err != nil {
		return nil, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	fresh := inserted == 1
	if !fresh {
		if s.indexUpdate != nil {
			_, err = s.indexUpdate.Exec(stamp, t.Client, 0, data, t.ID)
		} else {
			_, err = writer.Exec(indexUpdate, stamp, t.Client, 0, data, t.ID)
		}
		if err != nil {
			return nil, err
		}
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
	s.indexRead, s.indexInsert, s.indexUpdate = nil, nil, nil
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
