package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/session"
)

// publishTestGeneration builds and publishes a SQLite generation holding value.
func publishTestGeneration(t *testing.T, dir string, value int) string {
	t.Helper()
	build, err := createAnalysisBuild(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(index.Driver, analysisURL(filepath.Join(dir, build), "rw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE marker(value INTEGER); INSERT INTO marker VALUES(?)", value); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err = publishAnalysis(context.Background(), dir, build); err != nil {
		t.Fatal(err)
	}
	path, err := analysisDatabasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(path)
}

func analysisGenerations(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "analysis-*.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for i, file := range files {
		files[i] = filepath.Base(file)
	}
	sort.Strings(files)
	return files
}

func TestPublishKeepsCurrentAndPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	// A build from another analysis that is still running must survive, while
	// one left behind long ago is abandoned.
	running, err := createAnalysisBuild(dir)
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := createAnalysisBuild(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err = os.Chtimes(filepath.Join(dir, abandoned), old, old); err != nil {
		t.Fatal(err)
	}
	var published []string
	for value := range 4 {
		published = append(published, publishTestGeneration(t, dir, value))
	}
	want := []string{published[2], published[3]}
	sort.Strings(want)
	if got := analysisGenerations(t, dir); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("generations %v, want current and previous %v", got, want)
	}
	if _, err = os.Stat(filepath.Join(dir, running)); err != nil {
		t.Fatal("running build removed", err)
	}
	if _, err = os.Stat(filepath.Join(dir, abandoned)); !os.IsNotExist(err) {
		t.Fatal("abandoned build kept", err)
	}
}

func TestConcurrentPublishKeepsCurrentGeneration(t *testing.T) {
	dir := t.TempDir()
	const publishers = 16
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var builds []string
	for range publishers {
		build, err := createAnalysisBuild(dir)
		if err != nil {
			t.Fatal(err)
		}
		builds = append(builds, build)
	}
	start := make(chan struct{})
	errs := make(chan error, publishers)
	for _, build := range builds {
		go func() {
			<-start
			errs <- publishAnalysis(ctx, dir, build)
		}()
	}
	close(start)
	for range publishers {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if _, err := analysisDatabasePath(dir); err != nil {
		t.Fatalf("current generation unavailable after concurrent publications: %v", err)
	}
	if generations := analysisGenerations(t, dir); len(generations) != 2 {
		t.Fatalf("expected current and previous generations, got %v", generations)
	}
}

func TestPublishCanBeCanceledWhileWaitingForLock(t *testing.T) {
	dir := t.TempDir()
	current := publishTestGeneration(t, dir, 1)
	lock, err := os.OpenFile(filepath.Join(dir, analysisPublishLock), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := session.LockFile(lock, true); err != nil {
		t.Fatal(err)
	}
	defer session.UnlockFile(lock)
	build, err := createAnalysisBuild(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := publishAnalysis(ctx, dir, build); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("publication with a held lock returned %v", err)
	}
	if path, err := analysisDatabasePath(dir); err != nil || filepath.Base(path) != current {
		t.Fatalf("canceled publication changed current generation: %q, %v", path, err)
	}
}

func TestReaderKeepsRemovedGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps open generations until a later publication")
	}
	dir := t.TempDir()
	first := publishTestGeneration(t, dir, 7)
	reader, err := index.OpenReader(analysisURL(filepath.Join(dir, first), "ro"), storeReaders)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for value := range 2 {
		publishTestGeneration(t, dir, value)
	}
	if _, err = os.Stat(filepath.Join(dir, first)); !os.IsNotExist(err) {
		t.Fatal("old generation not removed", err)
	}
	// Hold every pooled connection at once: none may need to reopen the file.
	var wg sync.WaitGroup
	errs := make(chan error, storeReaders)
	ready, start := make(chan struct{}, storeReaders), make(chan struct{})
	for range storeReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := reader.Conn(context.Background())
			ready <- struct{}{}
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			<-start
			var value int
			if err = conn.QueryRowContext(context.Background(), "SELECT value FROM marker").Scan(&value); err == nil && value != 7 {
				err = os.ErrInvalid
			}
			errs <- err
		}()
	}
	for range storeReaders {
		<-ready
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("reader lost its generation", err)
		}
	}
}
