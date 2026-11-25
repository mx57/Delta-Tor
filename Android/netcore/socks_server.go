package netcore

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
)

// SocksServer is an authenticated local SOCKS5 server forwarding requests via a HopDialer.
type SocksServer struct {
	dialer     HopDialer
	username   string
	password   string
	listener   net.Listener
	udpConn    *net.UDPConn
	listenAddr string
	listenPort int
	closed     atomic.Bool
	wg         sync.WaitGroup
	connsMu    sync.Mutex
	conns      map[net.Conn]struct{}
	rxBytes    atomic.Int64
	txBytes    atomic.Int64
}

// NewSocksServer starts a local SOCKS5 proxy on bindAddr (e.g. "127.0.0.1:0") requiring user/pass auth.
func NewSocksServer(bindAddr string, username, password string, dialer HopDialer) (*SocksServer, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind socks5 listener on %s: %w", bindAddr, err)
	}

	tcpAddr := ln.Addr().(*net.TCPAddr)
	s := &SocksServer{
		dialer:     dialer,
		username:   username,
		password:   password,
		listener:   ln,
		listenAddr: tcpAddr.IP.String(),
		listenPort: tcpAddr.Port,
		conns:      make(map[net.Conn]struct{}),
	}

	s.wg.Add(1)
	go s.acceptLoop()

	return s, nil
}

func (s *SocksServer) Port() int {
	return s.listenPort
}

func (s *SocksServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *SocksServer) Stats() (int64, int64) {
	return s.rxBytes.Load(), s.txBytes.Load()
}

func (s *SocksServer) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	err := s.listener.Close()
	if s.udpConn != nil {
		s.udpConn.Close()
	}

	s.connsMu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.connsMu.Unlock()

	s.wg.Wait()
	return err
}

func (s *SocksServer) trackConn(c net.Conn) {
	s.connsMu.Lock()
	if s.closed.Load() {
		c.Close()
	} else {
		s.conns[c] = struct{}{}
	}
	s.connsMu.Unlock()
}

func (s *SocksServer) untrackConn(c net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

func (s *SocksServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		s.trackConn(conn)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(c)
			defer c.Close()
			s.handleConnection(c)
		}(conn)
	}
}

func (s *SocksServer) handleConnection(client net.Conn) {
	// 1. Negotiation
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	hasNoAuth := false
	hasUserPass := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
		if m == 0x02 {
			hasUserPass = true
		}
	}

	// Must authenticate if credentials are required
	if s.username != "" {
		if !hasUserPass {
			client.Write([]byte{0x05, 0xff}) // NO ACCEPTABLE METHODS
			return
		}
		client.Write([]byte{0x05, 0x02}) // USERNAME/PASSWORD (RFC 1929)

		// Read auth
		authVer := make([]byte, 1)
		if _, err := io.ReadFull(client, authVer); err != nil || authVer[0] != 0x01 {
			client.Write([]byte{0x01, 0x01})
			return
		}
		uLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, uLenBuf); err != nil {
			return
		}
		uLen := int(uLenBuf[0])
		userBuf := make([]byte, uLen)
		if _, err := io.ReadFull(client, userBuf); err != nil {
			return
		}

		pLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, pLenBuf); err != nil {
			return
		}
		pLen := int(pLenBuf[0])
		passBuf := make([]byte, pLen)
		if _, err := io.ReadFull(client, passBuf); err != nil {
			return
		}

		userOk := subtle.ConstantTimeCompare(userBuf, []byte(s.username)) == 1
		passOk := subtle.ConstantTimeCompare(passBuf, []byte(s.password)) == 1
		if !userOk || !passOk {
			client.Write([]byte{0x01, 0x01}) // Auth failure
			return
		}
		client.Write([]byte{0x01, 0x00}) // Auth success
	} else {
		if !hasNoAuth {
			client.Write([]byte{0x05, 0xff})
			return
		}
		client.Write([]byte{0x05, 0x00}) // NO AUTH
	}

	// 2. Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != 0x05 {
		return
	}
	cmd := reqHeader[1]
	atyp := reqHeader[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		dLen := make([]byte, 1)
		if _, err := io.ReadFull(client, dLen); err != nil {
			return
		}
		domain := make([]byte, int(dLen[0]))
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	switch cmd {
	case 0x01: // CONNECT
		s.handleConnect(client, targetAddr)
	case 0x03: // UDP ASSOCIATE
		s.handleUdpAssociate(client)
	default:
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
	}
}

func (s *SocksServer) handleConnect(client net.Conn, targetAddr string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetConn, err := s.dialer.DialTCP(ctx, targetAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer targetConn.Close()

	// Reply success: BND.ADDR 0.0.0.0:0
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Bidirectional pipe
	var once sync.Once
	closeBoth := func() {
		client.Close()
		targetConn.Close()
	}

	var copyWg sync.WaitGroup
	copyWg.Add(2)

	go func() {
		defer copyWg.Done()
		defer once.Do(closeBoth)
		buf := make([]byte, 32*1024)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				s.txBytes.Add(int64(n))
				if _, wErr := targetConn.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		defer copyWg.Done()
		defer once.Do(closeBoth)
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				s.rxBytes.Add(int64(n))
				if _, wErr := client.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

	copyWg.Wait()
}

func (s *SocksServer) handleUdpAssociate(client net.Conn) {
	// Bind a local UDP listener for relaying
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	uConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer uConn.Close()

	localUdpPort := uConn.LocalAddr().(*net.UDPAddr).Port
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1}
	pBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(pBytes, uint16(localUdpPort))
	resp = append(resp, pBytes...)
	if _, err := client.Write(resp); err != nil {
		return
	}

	// Keep connection alive until client disconnects
	buf := make([]byte, 1)
	for {
		if _, err := client.Read(buf); err != nil {
			return
		}
	}
}
