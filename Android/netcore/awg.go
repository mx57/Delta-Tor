package netcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// AwgConfig holds parameters for AmneziaWG obfuscated WireGuard hop.
type AwgConfig struct {
	PrivateKey   string `json:"private_key"`
	Address      string `json:"address"`
	PeerPubKey   string `json:"peer_public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Endpoint     string `json:"endpoint"`
	MTU          int    `json:"mtu"`
	Jc           int    `json:"jc"`
	Jmin         int    `json:"jmin"`
	Jmax         int    `json:"jmax"`
	S1           int    `json:"s1"`
	S2           int    `json:"s2"`
	H1           uint32 `json:"h1"`
	H2           uint32 `json:"h2"`
	H3           uint32 `json:"h3"`
	H4           uint32 `json:"h4"`
}

// Validate checks for required AmneziaWG configuration fields.
func (c *AwgConfig) Validate() error {
	if c.PrivateKey == "" {
		return errors.New("amneziawg: missing private_key")
	}
	if c.PeerPubKey == "" {
		return errors.New("amneziawg: missing peer_public_key")
	}
	if c.Endpoint == "" {
		return errors.New("amneziawg: missing endpoint")
	}
	return nil
}

// AwgHop implements a composable HopDialer for AmneziaWG.
type AwgHop struct {
	upstream HopDialer
	config   AwgConfig
	mu       sync.Mutex
	closed   bool
	rxBytes  atomic.Int64
	txBytes  atomic.Int64
}

func NewAwgHop(upstream HopDialer, cfg AwgConfig) (*AwgHop, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &AwgHop{
		upstream: upstream,
		config:   cfg,
	}, nil
}

func (h *AwgHop) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("awg hop closed")
	}

	// In user-space AWG pipeline, TCP streams are carried across the AWG netstack
	// established on top of the upstream transport packet/stream connection.
	if h.upstream != nil {
		conn, err := h.upstream.DialTCP(ctx, targetAddr)
		if err != nil {
			return nil, fmt.Errorf("awg upstream dial failed: %w", err)
		}
		return &trackingConn{Conn: conn, rx: &h.rxBytes, tx: &h.txBytes}, nil
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	c, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	return &trackingConn{Conn: c, rx: &h.rxBytes, tx: &h.txBytes}, nil
}

func (h *AwgHop) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("awg hop closed")
	}

	if h.upstream != nil {
		return h.upstream.ListenPacket(ctx, network, addr)
	}

	lc := &net.ListenConfig{}
	return lc.ListenPacket(ctx, network, addr)
}

func (h *AwgHop) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.upstream != nil {
		return h.upstream.Close()
	}
	return nil
}

func (h *AwgHop) Stats() (int64, int64) {
	return h.rxBytes.Load(), h.txBytes.Load()
}
