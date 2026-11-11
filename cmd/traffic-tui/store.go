package main

import (
	"database/sql"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Transaction = session.Transaction
type Alert = session.Alert
type Stats = session.Stats

const indexTimeFormat = session.IndexTimeFormat

// The analyst opens existing sessions read-only and keeps no capture state.
type Store struct {
	db  *sql.DB
	dir string
}

func openStore(dir string) (*Store, error) {
	db, err := session.OpenDB(dir, false)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, dir: dir}, nil
}
