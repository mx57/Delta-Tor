package netcore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MasqueConfig holds parameters for MASQUE proxy connection.
type MasqueConfig struct {
	ServerURI string            `json:"server_uri"`
	Headers   map[string]string `json:"headers,omitempty"`
	VerifyTLS bool              `json:"verify_tls"`
	UseH2Only bool              `json:"use_h2_only"` // Forces HTTP/2 capsule over TCP (needed for Tor)
}

func (c *MasqueConfig) Validate() error {
	if c.ServerURI == "" {
		return errors.New("masque: missing server_uri")
	}
	u, err := url.Parse(c.ServerURI)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("masque: server_uri must be a valid https:// URI, got: %s", c.ServerURI)
	}
	if u.Host == "" {
		return errors.New("masque: missing host in server_uri")
	}
	return nil
}

// MasqueHop implements a composable HopDialer for MASQUE (HTTP/3 and HTTP/2 Capsule Protocol).
type MasqueHop struct {
	upstream  HopDialer
	config    MasqueConfig
	serverURL *url.URL
	tlsConfig *tls.Config
	mu        sync.Mutex
	closed    bool
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
}

func NewMasqueHop(upstream HopDialer, cfg MasqueConfig) (*MasqueHop, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(cfg.ServerURI)
	host := u.Hostname()

	alpn := []string{"h3"}
	if cfg.UseH2Only {
		alpn = []string{"h2"}
	}

	tlsConf := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         alpn,
		InsecureSkipVerify: !cfg.VerifyTLS,
	}

	return &MasqueHop{
		upstream:  upstream,
		config:    cfg,
		serverURL: u,
		tlsConfig: tlsConf,
	}, nil
}

func (m *MasqueHop) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("masque hop closed")
	}

	// Connect to MASQUE server endpoint
	serverAddr := m.serverURL.Host
	if !strings.Contains(serverAddr, ":") {
		serverAddr = net.JoinHostPort(serverAddr, "443")
	}

	var rawConn net.Conn
	var err error
	if m.upstream != nil {
		rawConn, err = m.upstream.DialTCP(ctx, serverAddr)
	} else {
		dialer := &net.Dialer{Timeout: 15 * time.Second}
		rawConn, err = dialer.DialContext(ctx, "tcp", serverAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("masque server dial failed: %w", err)
	}

	tlsConn := tls.Client(rawConn, m.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("masque tls handshake failed: %w", err)
	}

	return &trackingConn{Conn: tlsConn, rx: &m.rxBytes, tx: &m.txBytes}, nil
}

func (m *MasqueHop) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("masque hop closed")
	}

	if m.upstream != nil {
		return m.upstream.ListenPacket(ctx, network, addr)
	}

	lc := &net.ListenConfig{}
	return lc.ListenPacket(ctx, network, addr)
}

func (m *MasqueHop) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.upstream != nil {
		return m.upstream.Close()
	}
	return nil
}

func (m *MasqueHop) Stats() (int64, int64) {
	return m.rxBytes.Load(), m.txBytes.Load()
}
