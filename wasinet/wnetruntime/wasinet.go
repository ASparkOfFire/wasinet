//go:build !wasip1 && !windows

package wnetruntime

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/asparkoffire/wasinet/wasinet/internal/langx"
	"golang.org/x/sys/unix"
)

const (
	Namespace = "wasinet_v0"
)

const (
	WASI_AF_INET  = 2
	WASI_AF_INET6 = 3
)

// Socket interface
type Socket interface {
	Open(ctx context.Context, af, socktype, protocol int) (fd int, err error)
	Bind(ctx context.Context, fd int, sa unix.Sockaddr) error
	Connect(ctx context.Context, fd int, sa unix.Sockaddr) error
	Listen(ctx context.Context, fd, backlog int) error
	Accept(ctx context.Context, fd int) (nfd int, sa unix.Sockaddr, err error)
	LocalAddr(ctx context.Context, fd int) (unix.Sockaddr, error)
	PeerAddr(ctx context.Context, fd int) (unix.Sockaddr, error)
	SetSocketOption(ctx context.Context, fd int, level, name int, value []byte) error
	GetSocketOption(ctx context.Context, fd int, level, name int, value []byte) (any, error)
	Shutdown(ctx context.Context, fd, how int) error
	AddrIP(ctx context.Context, network string, address string) ([]net.IP, error)
	AddrPort(ctx context.Context, network string, service string) (int, error)
	GetAddrInfo(ctx context.Context, node, service string, hints *AddrInfo) ([]AddrInfo, error)
	RecvFrom(ctx context.Context, fd int, vecs [][]byte, oob []byte, flags int) (int, int, unix.Sockaddr, error)
	SendTo(ctx context.Context, fd int, sa unix.Sockaddr, vecs [][]byte, oob []byte, flags int) (int, error)
}

// AddrInfo represents address information similar to struct addrinfo in C
type AddrInfo struct {
	Flags    int32
	Family   int32
	SockType int32
	Protocol int32
	Addr     unix.Sockaddr
}

type IP interface {
	Allow(...netip.Prefix) IP
}

type FSPrefix struct {
	Host  string
	Guest string
}

type fsremap []FSPrefix

func (t fsremap) Remap(s string) (r string) {
	var (
		best FSPrefix
	)

	for _, m := range t {
		if !strings.HasPrefix(s, m.Guest) {
			continue
		}

		if len(m.Guest) < len(best.Guest) {
			continue
		}

		best = m
	}

	return filepath.Join(best.Host, strings.TrimPrefix(s, best.Guest))
}

type Option func(*network)

func OptionAllow(cidrs ...netip.Prefix) Option {
	return func(s *network) {
		s.allow = append(s.allow, cidrs...)
	}
}

func OptionFSPrefixes(prefixes ...FSPrefix) Option {
	return func(n *network) {
		n.fsmap = prefixes
	}
}

// unrestricted network defaults.
func Unrestricted(opts ...Option) Socket {
	return langx.Autoptr(
		langx.Clone(
			network{},
			opts...,
		),
	)
}

// the network by default disallows all network activity. use unrestricted
// or manually configure using options.
func New(opts ...Option) Socket {
	return langx.Autoptr(langx.Clone(network{}, opts...))
}

type network struct {
	allow []netip.Prefix
	fsmap []FSPrefix
}

func (t network) Bind(ctx context.Context, fd int, sa unix.Sockaddr) error {
	// slog.Log(ctx, slog.LevelDebug, "sock_bind", slog.Int("fd", fd), slog.String("addr", fmt.Sprintf("%v", sa)))
	return unix.Bind(fd, sa)
}

func (t network) Connect(ctx context.Context, fd int, sa unix.Sockaddr) (err error) {
	switch actual := sa.(type) {
	case *unix.SockaddrUnix:
		remapped := fsremap(t.fsmap).Remap(actual.Name)
		if p, err := unix.Getsockname(fd); err != nil {
			return err
		} else {
			*actual = *p.(*unix.SockaddrUnix)
			actual.Name = remapped
		}

		return unix.Connect(fd, actual)
	default:
		// slog.Log(ctx, slog.LevelDebug, "sock_connect", slog.Int("fd", fd), slog.String("addr", fmt.Sprintf("%v", sa)))
		return unix.Connect(fd, sa)
	}
}

func (t network) Listen(ctx context.Context, fd, backlog int) error {
	// slog.Log(ctx, slog.LevelDebug, "sock_listen", slog.Int("fd", fd), slog.Int("backlog", backlog))
	return unix.Listen(fd, backlog)
}

func (t network) Accept(ctx context.Context, fd int) (nfd int, sa unix.Sockaddr, err error) {
	// slog.Log(ctx, slog.LevelDebug, "sock_accept", slog.Int("fd", fd))
	return unix.Accept(fd)
}

func (t network) LocalAddr(ctx context.Context, fd int) (unix.Sockaddr, error) {
	// slog.Log(ctx, slog.LevelDebug, "sock_localaddr", slog.Int("fd", fd))
	return unix.Getsockname(fd)
}

func (t network) PeerAddr(ctx context.Context, fd int) (_ unix.Sockaddr, err error) {
	// slog.Log(ctx, slog.LevelDebug, "sock_peeraddr", slog.Int("fd", fd))
	return unix.Getpeername(fd)
}

func (t network) Shutdown(ctx context.Context, fd, how int) error {
	// slog.Log(ctx, slog.LevelDebug, "sock_shutdown", slog.Int("fd", fd), slog.Int("how", how))
	return unix.Shutdown(fd, how)
}

func (t network) AddrIP(ctx context.Context, network string, address string) ([]net.IP, error) {
	// slog.Log(ctx, slog.LevelDebug, "sock_getaddrip", slog.String("network", network), slog.String("address", address))
	return net.DefaultResolver.LookupIP(ctx, network, address)
}

func (t network) AddrPort(ctx context.Context, network string, service string) (int, error) {
	// slog.Log(ctx, slog.LevelDebug, "sock_getaddrport", slog.String("network", network), slog.String("service", service))
	return net.DefaultResolver.LookupPort(ctx, network, service)
}

func (t network) GetAddrInfo(ctx context.Context, node, service string, hints *AddrInfo) ([]AddrInfo, error) {
	// Convert node and service to IP addresses and ports
	var err error
	var network string

	// Determine network type from hints
	if hints != nil {
		switch hints.Family {
		case unix.AF_INET:
			network = "ip4"
		case unix.AF_INET6:
			network = "ip6"
		default:
			network = "ip"
		}
	} else {
		network = "ip"
	}

	// If node is empty and service is not, lookup service port first
	if node == "" && service != "" {
		port, err := t.AddrPort(ctx, network, service)
		if err != nil {
			return nil, err
		}

		// Create appropriate socket address for loopback
		var result []AddrInfo

		// Add IPv4 loopback if family allows it
		if hints == nil || hints.Family == unix.AF_INET || hints.Family == unix.AF_UNSPEC {
			addr := &unix.SockaddrInet4{Port: port}
			addr.Addr[0] = 127
			addr.Addr[3] = 1

			info := AddrInfo{
				Family:   unix.AF_INET,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		}

		// Add IPv6 loopback if family allows it
		if hints == nil || hints.Family == unix.AF_INET6 || hints.Family == unix.AF_UNSPEC {
			addr := &unix.SockaddrInet6{Port: port}
			addr.Addr[15] = 1 // ::1

			info := AddrInfo{
				Family:   unix.AF_INET6,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		}

		return result, nil
	}

	// Try to parse node as IP address first
	if ip := net.ParseIP(node); ip != nil {
		// Create appropriate sockaddr based on IP version
		var result []AddrInfo

		if ip.To4() != nil && (hints == nil || hints.Family == unix.AF_INET || hints.Family == unix.AF_UNSPEC) {
			// IPv4 address
			var port int
			if service != "" {
				port, err = t.AddrPort(ctx, network, service)
				if err != nil {
					return nil, err
				}
			}

			addr := &unix.SockaddrInet4{Port: port}
			copy(addr.Addr[:], ip.To4())

			info := AddrInfo{
				Family:   unix.AF_INET,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		} else if hints == nil || hints.Family == unix.AF_INET6 || hints.Family == unix.AF_UNSPEC {
			// IPv6 address
			var port int
			if service != "" {
				port, err = t.AddrPort(ctx, network, service)
				if err != nil {
					return nil, err
				}
			}

			addr := &unix.SockaddrInet6{Port: port}
			copy(addr.Addr[:], ip.To16())

			info := AddrInfo{
				Family:   unix.AF_INET6,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		}

		return result, nil
	}

	// Look up the hostname
	ips, err := t.AddrIP(ctx, network, node)
	if err != nil {
		return nil, err
	}

	// Get the service port if provided
	var port int
	if service != "" {
		port, err = t.AddrPort(ctx, network, service)
		if err != nil {
			return nil, err
		}
	}

	// Create AddrInfo entries for each resolved IP
	var result []AddrInfo
	for _, ip := range ips {
		if ip.To4() != nil && (hints == nil || hints.Family == unix.AF_INET || hints.Family == unix.AF_UNSPEC) {
			// IPv4 address
			addr := &unix.SockaddrInet4{Port: port}
			copy(addr.Addr[:], ip.To4())

			info := AddrInfo{
				Family:   unix.AF_INET,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		} else if hints == nil || hints.Family == unix.AF_INET6 || hints.Family == unix.AF_UNSPEC {
			// IPv6 address
			addr := &unix.SockaddrInet6{Port: port}
			copy(addr.Addr[:], ip.To16())

			info := AddrInfo{
				Family:   unix.AF_INET6,
				SockType: hints.SockType,
				Protocol: hints.Protocol,
				Addr:     addr,
			}
			result = append(result, info)
		}
	}

	return result, nil
}

func (t network) RecvFrom(ctx context.Context, fd int, vecs [][]byte, oob []byte, flags int) (int, int, unix.Sockaddr, error) {
	n, _, roflags, sa, err := unix.RecvmsgBuffers(fd, vecs, oob, flags)
	return n, roflags, sa, err
}

func (t network) SendTo(ctx context.Context, fd int, sa unix.Sockaddr, vecs [][]byte, oob []byte, flags int) (int, error) {
	// dispatch-run/wasi-go has linux special cased here.
	// did not faithfully follow it because it might be caused by other complexity.
	// https://github.com/dispatchrun/wasi-go/blob/038d5104aacbb966c25af43797473f03c5da3e4f/systems/unix/system.go#L640
	switch sa.(type) {
	case *unix.SockaddrUnix:
		// apparently its fine to send the sock address to a tcp stream
		// but for unix sockets it'll return syscall.EISCONN
		return unix.SendmsgBuffers(int(fd), vecs, oob, nil, int(flags))
	default:
		return unix.SendmsgBuffers(int(fd), vecs, oob, sa, int(flags))
	}
}
