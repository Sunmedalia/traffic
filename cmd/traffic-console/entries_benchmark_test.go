package main

import (
	"context"
	"strings"
	"testing"
)

// BenchmarkStoreQueries compares the entries table with the JSON views older
// generations use, on records carrying 16 KiB request and response bodies:
//
//	go test ./cmd/traffic-console -run '^$' -bench StoreQueries
func BenchmarkStoreQueries(b *testing.B) {
	dir := legacyEntriesSession(b, 2000, 16<<10)
	analyzeEntriesSession(b, dir)
	queries := []struct {
		name   string
		filter tuiFilter
		query  string
	}{
		{"count_method", tuiFilter{Method: "POST"}, "SELECT count(*) FROM entries WHERE "},
		{"status_classes", tuiFilter{}, "SELECT status/100,count(*) FROM entries WHERE %s GROUP BY 1"},
		{"alerts_by_severity", tuiFilter{}, "SELECT severity,count(*) FROM entries WHERE alert>0 AND %s GROUP BY 1"},
		{"page_10", tuiFilter{Keyword: "test"}, "SELECT id,method,host,url,status,severity,rule FROM entries WHERE %s ORDER BY time DESC,id DESC LIMIT 100 OFFSET 1000"},
	}
	run := func(b *testing.B, layout string) {
		store, err := openStore(dir)
		if err != nil {
			b.Fatal(err)
		}
		defer store.db.Close()
		for _, q := range queries {
			where, args := q.filter.where(false)
			query := q.query + where
			if i := strings.Index(q.query, "%s"); i >= 0 {
				query = q.query[:i] + where + q.query[i+2:]
			}
			b.Run(layout+"/"+q.name, func(b *testing.B) {
				for b.Loop() {
					rows, err := store.db.QueryContext(context.Background(), query, args...)
					if err != nil {
						b.Fatal(err)
					}
					for rows.Next() {
					}
					if err = rows.Err(); err != nil {
						b.Fatal(err)
					}
					rows.Close()
				}
			})
		}
	}
	run(b, "entries")
	downgradeAnalysis(b, dir)
	run(b, "json_view")
}
