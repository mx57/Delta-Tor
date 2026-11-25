package netcore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// HopDialer defines the composable interface implemented by each link in a multi-hop chain.
type HopDialer interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
	Close() error
	Stats() (rxBytes, txBytes int64)
}

// SocketProtector allows exempting raw socket file descriptors from the VPN TUN interface.
type SocketProtector interface {
	Protect(fd int) bool
}

// trackingConn wraps net.Conn to record rx/tx traffic statistics.
type trackingConn struct {
	net.Conn
	rx *atomic.Int64
	tx *atomic.Int64
}

func (c *trackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.rx != nil {
		c.rx.Add(int64(n))
	}
	return n, err
}

func (c *trackingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.tx != nil {
		c.tx.Add(int64(n))
	}
	return n, err
}

// trackingPacketConn wraps net.PacketConn to record rx/tx traffic statistics.
type trackingPacketConn struct {
	net.PacketConn
	rx *atomic.Int64
	tx *atomic.Int64
}

func (c *trackingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 && c.rx != nil {
		c.rx.Add(int64(n))
	}
	return n, addr, err
}

func (c *trackingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 && c.tx != nil {
		c.tx.Add(int64(n))
	}
	return n, err
}

// ProtectedDirectDialer dials sockets directly, exempting them from VPN routing via SocketProtector.
type ProtectedDirectDialer struct {
	protector SocketProtector
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
}

func NewProtectedDirectDialer(protector SocketProtector) *ProtectedDirectDialer {
	return &ProtectedDirectDialer{
		protector: protector,
	}
}

func (d *ProtectedDirectDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if d.protector != nil {
				return c.Control(func(fd uintptr) {
					d.protector.Protect(int(fd))
				})
			}
			return nil
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &trackingConn{Conn: conn, rx: &d.rxBytes, tx: &d.txBytes}, nil
}

func (d *ProtectedDirectDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if d.protector != nil {
				return c.Control(func(fd uintptr) {
					d.protector.Protect(int(fd))
				})
			}
			return nil
		},
	}
	pc, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &trackingPacketConn{PacketConn: pc, rx: &d.rxBytes, tx: &d.txBytes}, nil
}

func (d *ProtectedDirectDialer) Close() error {
	return nil
}

func (d *ProtectedDirectDialer) Stats() (int64, int64) {
	return d.rxBytes.Load(), d.txBytes.Load()
}

// Socks5HopDialer connects to an upstream SOCKS5 proxy (Tor or SSTP) over an existing HopDialer.
type Socks5HopDialer struct {
	upstream HopDialer
	proxyAddr string
	username  string
	password  string
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
}

func NewSocks5HopDialer(upstream HopDialer, proxyAddr, username, password string) *Socks5HopDialer {
	return &Socks5HopDialer{
		upstream:  upstream,
		proxyAddr: proxyAddr,
		username:  username,
		password:  password,
	}
}

func (s *Socks5HopDialer) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	var conn net.Conn
	var err error
	if s.upstream != nil {
		conn, err = s.upstream.DialTCP(ctx, s.proxyAddr)
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err = dialer.DialContext(ctx, "tcp", s.proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("socks5 connect upstream %s failed: %w", s.proxyAddr, err)
	}

	// 1. Handshake
	methods := []byte{0x05, 0x01, 0x00}
	if s.username != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02} // NO AUTH (0x00) and USER/PASS (0x02)
	}
	if _, err := conn.Write(methods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting write failed: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting read failed: %w", err)
	}
	if reply[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("unsupported socks version: %d", reply[0])
	}

	// 2. Auth if requested
	if reply[1] == 0x02 { // Username/Password auth (RFC 1929)
		if s.username == "" {
			conn.Close()
			return nil, errors.New("socks5 server requested auth but none provided")
		}
		uLen := byte(len(s.username))
		pLen := byte(len(s.password))
		req := make([]byte, 0, 3+len(s.username)+len(s.password))
		req = append(req, 0x01, uLen)
		req = append(req, []byte(s.username)...)
		req = append(req, pLen)
		req = append(req, []byte(s.password)...)
		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth write failed: %w", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth read failed: %w", err)
		}
		if authReply[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth rejected with status: 0x%02x", authReply[1])
		}
	} else if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 server rejected auth methods with code 0x%02x", reply[1])
	}

	// 3. Connect request
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address %s: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port %s", portStr)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect request write failed: %w", err)
	}

	connReply := make([]byte, 4)
	if _, err := io.ReadFull(conn, connReply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply header read failed: %w", err)
	}
	if connReply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect command failed with code 0x%02x", connReply[1])
	}

	// Drain bound address
	switch connReply[3] {
	case 0x01: // IPv4
		b := make([]byte, 4+2)
		io.ReadFull(conn, b)
	case 0x03: // FQDN
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		b := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, b)
	case 0x04: // IPv6
		b := make([]byte, 16+2)
		io.ReadFull(conn, b)
	}

	return &trackingConn{Conn: conn, rx: &s.rxBytes, tx: &s.txBytes}, nil
}

func (s *Socks5HopDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// For UDP Associate over SOCKS5:
	// If upstream doesn't support UDP associate (like plain Tor), callers use UoT adapter.
	return nil, errors.New("socks5 native UDP ASSOCIATE requires UoT adapter on TCP-only links")
}

func (s *Socks5HopDialer) Close() error {
	if s.upstream != nil {
		return s.upstream.Close()
	}
	return nil
}

func (s *Socks5HopDialer) Stats() (int64, int64) {
	return s.rxBytes.Load(), s.txBytes.Load()
}
