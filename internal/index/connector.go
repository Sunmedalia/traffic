package index

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
)

// Statement is SQL run on every new pooled connection, such as ATTACH or a
// TEMP VIEW. Temporary objects are connection-local, so running them per
// connection lets read-only stores use more than one connection.
type Statement struct {
	SQL  string
	Args []any
}

type setupConnector struct {
	dsn   string
	setup []Statement
}

func (c setupConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := sqliteDriver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		conn.Close()
		return nil, errors.New("SQLite connection cannot execute setup statements")
	}
	for _, statement := range c.setup {
		args := make([]driver.NamedValue, len(statement.Args))
		for i, value := range statement.Args {
			args[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
		}
		if _, err = execer.ExecContext(ctx, statement.SQL, args); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (c setupConnector) Driver() driver.Driver { return sqliteDriver }

// OpenReader opens dsn with up to conns pooled connections, each prepared by
// setup, and verifies that the first connection can be established.
func OpenReader(dsn string, conns int, setup ...Statement) (*sql.DB, error) {
	db := sql.OpenDB(setupConnector{dsn: dsn, setup: setup})
	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(conns)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
