package replay

import (
	"bufio"
	"io"
)

// Channels bound retained buffers (unlike sync.Pool) and never wait for reuse.
// Reset(nil) removes references to a connection or large message before return.
var httpReaders = [...]struct {
	size int
	idle chan *bufio.Reader
}{
	{256, make(chan *bufio.Reader, 32)}, {1024, make(chan *bufio.Reader, 32)},
	{4096, make(chan *bufio.Reader, 32)}, {32768, make(chan *bufio.Reader, 32)},
}

func borrowHTTPReader(source io.Reader, size int) (*bufio.Reader, func()) {
	bucket := &httpReaders[len(httpReaders)-1]
	for i := range httpReaders {
		if size <= httpReaders[i].size {
			bucket = &httpReaders[i]
			break
		}
	}
	var reader *bufio.Reader
	select {
	case reader = <-bucket.idle:
		reader.Reset(source)
	default:
		reader = bufio.NewReaderSize(source, bucket.size)
	}
	return reader, func() {
		reader.Reset(nil)
		select {
		case bucket.idle <- reader:
		default:
		}
	}
}
