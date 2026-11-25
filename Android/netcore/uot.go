package netcore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// UoTAdapter provides a virtual net.PacketConn (UDP) over a stream-based HopDialer (TCP).
// Uses UoT v2 framing: [2-byte big-endian frame len] [1-byte ATYP] [Dest Addr] [2-byte Port] [Payload]
type UoTAdapter struct {
	stream net.Conn
	mu     sync.Mutex
	closed bool
}

func NewUoTAdapter(stream net.Conn) *UoTAdapter {
	return &UoTAdapter{stream: stream}
}

// DialUoT opens a TCP stream to the UoT relay via the provided HopDialer and returns a PacketConn.
func DialUoT(ctx context.Context, dialer HopDialer, relayAddr string) (net.PacketConn, error) {
	conn, err := dialer.DialTCP(ctx, relayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UoT relay %s: %w", relayAddr, err)
	}
	return NewUoTAdapter(conn), nil
}

func (u *UoTAdapter) ReadFrom(p []byte) (int, net.Addr, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, nil, errors.New("closed")
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(u.stream, lenBuf); err != nil {
		return 0, nil, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf))
	if frameLen < 4 {
		return 0, nil, errors.New("invalid uot frame length")
	}

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(u.stream, frame); err != nil {
		return 0, nil, err
	}

	atyp := frame[0]
	var host string
	var offset int
	switch atyp {
	case 0x01: // IPv4
		if len(frame) < 1+4+2 {
			return 0, nil, errors.New("uot frame truncated ipv4")
		}
		host = net.IP(frame[1:5]).String()
		offset = 5
	case 0x03: // Domain
		dLen := int(frame[1])
		if len(frame) < 2+dLen+2 {
			return 0, nil, errors.New("uot frame truncated domain")
		}
		host = string(frame[2 : 2+dLen])
		offset = 2 + dLen
	case 0x04: // IPv6
		if len(frame) < 1+16+2 {
			return 0, nil, errors.New("uot frame truncated ipv6")
		}
		host = net.IP(frame[1:17]).String()
		offset = 17
	default:
		return 0, nil, fmt.Errorf("unknown atyp 0x%02x in uot frame", atyp)
	}

	port := binary.BigEndian.Uint16(frame[offset : offset+2])
	offset += 2
	payload := frame[offset:]

	n := copy(p, payload)
	addr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	return n, addr, nil
}

func (u *UoTAdapter) WriteTo(p []byte, addr net.Addr) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, errors.New("closed")
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}

	var header []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = make([]byte, 1+4+2)
			header[0] = 0x01
			copy(header[1:5], ip4)
			binary.BigEndian.PutUint16(header[5:7], uint16(port))
		} else {
			header = make([]byte, 1+16+2)
			header[0] = 0x04
			copy(header[1:17], ip.To16())
			binary.BigEndian.PutUint16(header[17:19], uint16(port))
		}
	} else {
		header = make([]byte, 2+len(host)+2)
		header[0] = 0x03
		header[1] = byte(len(host))
		copy(header[2:2+len(host)], []byte(host))
		binary.BigEndian.PutUint16(header[2+len(host):], uint16(port))
	}

	totalLen := len(header) + len(p)
	if totalLen > 65535 {
		return 0, errors.New("payload exceeds maximum uot frame size")
	}

	frame := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
	copy(frame[2:2+len(header)], header)
	copy(frame[2+len(header):], p)

	if _, err := u.stream.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *UoTAdapter) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	return u.stream.Close()
}

func (u *UoTAdapter) LocalAddr() net.Addr {
	return u.stream.LocalAddr()
}

func (u *UoTAdapter) SetDeadline(t time.Time) error {
	return u.stream.SetDeadline(t)
}

func (u *UoTAdapter) SetReadDeadline(t time.Time) error {
	return u.stream.SetReadDeadline(t)
}

func (u *UoTAdapter) SetWriteDeadline(t time.Time) error {
	return u.stream.SetWriteDeadline(t)
}
