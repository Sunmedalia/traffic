package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// kernelListeners returns the listening TCP sockets (socket inode -> port) in
// the network namespace of the /proc process directory dir. It asks sock_diag
// for LISTEN sockets only, so the kernel walks just its listening hash.
// /proc/net/tcp and tcp6 instead format every socket in the namespace,
// established and TIME_WAIT included, under each hash bucket lock with bottom
// halves disabled: on a busy website that was the costliest part of a target
// refresh, and the part that competed with the site's own packet processing.
// Callers fall back to the /proc tables on any error.
func kernelListeners(dir string) (map[string]int, error) {
	if sockDiagUnavailable.Load() {
		return nil, errSockDiagUnavailable
	}
	listeners, err := queryKernelListeners(dir)
	var kernelErr sockDiagError
	if errors.As(err, &kernelErr) {
		sockDiagUnavailable.Store(true)
	}
	return listeners, err
}

// sockDiagUnavailable is set once the kernel itself rejects a sock_diag
// socket or dump. A missing inet_diag/tcp_diag module can make every attempt
// spawn modprobe on the website's host, so a failing kernel is not asked
// again. Errors tied to one process (it exited, or its namespace cannot be
// entered) do not set it.
var sockDiagUnavailable atomic.Bool

var errSockDiagUnavailable = errors.New("sock_diag unavailable on this kernel")

type sockDiagError struct{ err error }

func (e sockDiagError) Error() string { return e.err.Error() }
func (e sockDiagError) Unwrap() error { return e.err }

func queryKernelListeners(dir string) (map[string]int, error) {
	fd, err := diagSocketIn(filepath.Join(dir, "ns", "net"))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	listeners := map[string]int{}
	for sequence, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := dumpListeners(fd, family, uint32(sequence+1), listeners); err != nil {
			return nil, sockDiagError{err}
		}
	}
	return listeners, nil
}

// diagSocketIn opens a sock_diag socket bound to the network namespace file.
// A netlink socket keeps the namespace it was created in, so only creation
// runs on a locked thread inside the target namespace; the dump itself runs
// after the thread is restored. Like inCaptureNamespace, a thread that cannot
// be restored is never returned to the Go scheduler.
func diagSocketIn(namespace string) (int, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		fd, restored, err := openDiagSocketLocked(namespace)
		if restored {
			runtime.UnlockOSThread()
		}
		done <- result{fd, err}
	}()
	r := <-done
	return r.fd, r.err
}

func openDiagSocketLocked(namespace string) (fd int, restored bool, err error) {
	target, err := os.Open(namespace)
	if err != nil {
		return -1, true, err
	}
	defer target.Close()
	original, err := os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/ns/net")
	if err != nil {
		return -1, true, err
	}
	defer original.Close()
	var want, have unix.Stat_t
	if err := unix.Fstat(int(target.Fd()), &want); err != nil {
		return -1, true, err
	}
	if err := unix.Fstat(int(original.Fd()), &have); err != nil {
		return -1, true, err
	}
	if want.Dev == have.Dev && want.Ino == have.Ino {
		fd, err := newDiagSocket()
		return fd, true, err
	}
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return -1, true, fmt.Errorf("enter network namespace: %w", err)
	}
	fd, err = newDiagSocket()
	if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return -1, false, fmt.Errorf("restore discovery thread namespace: %w", restore)
	}
	return fd, true, err
}

func newDiagSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return -1, sockDiagError{err}
	}
	// Discovery must never hang on a kernel that does not answer.
	timeout := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		unix.Close(fd)
		return -1, sockDiagError{err}
	}
	return fd, nil
}

const (
	tcpListenState = 10 // TCP_LISTEN, the "0A" state in /proc/net/tcp
	// struct inet_diag_req_v2: family, protocol, ext, pad, states, then the
	// 48-byte inet_diag_sockid left zero (no address filter).
	inetDiagRequestLength = 56
	// struct inet_diag_msg: family, state, timer, retrans, then the
	// 48-byte sockid (sport and dport in network byte order), expires,
	// rqueue, wqueue, uid and inode.
	inetDiagMessageLength = 72
	inetDiagSourcePort    = 4
	inetDiagInode         = 68
)

func dumpListeners(fd int, family uint8, sequence uint32, listeners map[string]int) error {
	request := make([]byte, unix.NLMSG_HDRLEN+inetDiagRequestLength)
	binary.NativeEndian.PutUint32(request[0:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	body := request[unix.NLMSG_HDRLEN:]
	body[0] = family
	body[1] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(body[4:], 1<<tcpListenState)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sock_diag request: %w", err)
	}
	buffer := make([]byte, 64<<10)
	for {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if errors.Is(err, unix.EINTR) {
			// A receive timeout disables SA_RESTART; Go's preemption
			// signals would otherwise turn into spurious fallbacks.
			continue
		}
		if err != nil {
			return fmt.Errorf("sock_diag receive: %w", err)
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return fmt.Errorf("sock_diag parse: %w", err)
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				if len(message.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(message.Data)); code < 0 {
						return fmt.Errorf("sock_diag: %w", syscall.Errno(-code))
					}
				}
				return errors.New("sock_diag: malformed error reply")
			case unix.SOCK_DIAG_BY_FAMILY:
				data := message.Data
				if len(data) < inetDiagMessageLength || data[1] != tcpListenState {
					continue
				}
				port := binary.BigEndian.Uint16(data[inetDiagSourcePort:])
				inode := binary.NativeEndian.Uint32(data[inetDiagInode:])
				listeners[strconv.FormatUint(uint64(inode), 10)] = int(port)
			}
		}
	}
}
