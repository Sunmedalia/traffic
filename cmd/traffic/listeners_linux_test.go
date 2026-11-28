package main

import (
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func listenerInode(t *testing.T, listener net.Listener) string {
	t.Helper()
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		t.Fatal(err)
	}
	inode, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		t.Fatalf("listener fd is %q", target)
	}
	return strings.TrimSuffix(inode, "]")
}

// sock_diag must report the same listening sockets as /proc/net/tcp{,6}, with
// inodes that match the socket:[N] descriptor links discovery resolves.
func TestKernelListenersMatchProcTables(t *testing.T) {
	var listeners []net.Listener
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			if address == "[::1]:0" {
				continue // no IPv6 loopback on this host
			}
			t.Fatal(err)
		}
		defer listener.Close()
		listeners = append(listeners, listener)
	}
	kernel, err := queryKernelListeners("/proc/self")
	if err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}
	proc := procListeners("/proc/self/net")
	for _, listener := range listeners {
		inode := listenerInode(t, listener)
		port := listener.Addr().(*net.TCPAddr).Port
		if kernel[inode] != port || proc[inode] != port {
			t.Fatalf("listener %s inode %s: sock_diag port %d, /proc port %d", listener.Addr(), inode, kernel[inode], proc[inode])
		}
	}
	// Other test binaries may open and close listeners concurrently, so only
	// sockets present in both snapshots must agree.
	for inode, port := range kernel {
		if other, ok := proc[inode]; ok && other != port {
			t.Fatalf("inode %s: sock_diag port %d, /proc port %d", inode, port, other)
		}
	}
	tables := map[string]map[string]int{}
	ports := listeningPortsSnapshot("/proc", "/proc/self", tables)
	for _, listener := range listeners {
		if !slices.Contains(ports, listener.Addr().(*net.TCPAddr).Port) {
			t.Fatalf("discovery ports %v miss %s", ports, listener.Addr())
		}
	}
}

// A process that exits mid-scan must not disable sock_diag for later scans.
func TestKernelListenersProcessErrorKeepsFastPath(t *testing.T) {
	if sockDiagUnavailable.Load() {
		t.Skip("sock_diag already unavailable in this process")
	}
	if _, err := kernelListeners(t.TempDir()); err == nil {
		t.Fatal("missing namespace file accepted")
	}
	if sockDiagUnavailable.Load() {
		t.Fatal("per-process error disabled sock_diag")
	}
}
