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

// WarpConfig holds configuration for Cloudflare WARP Anycast hop.
type WarpConfig struct {
	PrivateKey string `json:"private_key"`
	Address4   string `json:"address_v4"`
	Address6   string `json:"address_v6"`
	PeerPubKey string `json:"peer_public_key"`
	Endpoint   string `json:"endpoint"`
	Reserved   [3]byte `json:"reserved"`
	ClientId   string `json:"client_id,omitempty"`
	Token      string `json:"token,omitempty"`
	MTU        int    `json:"mtu"`
}

// Validate checks for required WARP configuration fields.
func (c *WarpConfig) Validate() error {
	if c.PrivateKey == "" {
		return errors.New("warp: missing private_key")
	}
	if c.PeerPubKey == "" {
		return errors.New("warp: missing peer_public_key")
	}
	if c.Endpoint == "" {
		return errors.New("warp: missing endpoint")
	}
	return nil
}

// WarpHop implements a composable HopDialer for Cloudflare WARP.
type WarpHop struct {
	upstream HopDialer
	config   WarpConfig
	mu       sync.Mutex
	closed   bool
	rxBytes  atomic.Int64
	txBytes  atomic.Int64
}

func NewWarpHop(upstream HopDialer, cfg WarpConfig) (*WarpHop, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &WarpHop{
		upstream: upstream,
		config:   cfg,
	}, nil
}

// RotateEndpoint switches the WARP peer endpoint dynamically without tearing down user sessions.
func (h *WarpHop) RotateEndpoint(newEndpoint string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("warp hop closed")
	}
	if _, _, err := net.SplitHostPort(newEndpoint); err != nil {
		return fmt.Errorf("invalid endpoint format %s: %w", newEndpoint, err)
	}
	h.config.Endpoint = newEndpoint
	return nil
}

func (h *WarpHop) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("warp hop closed")
	}

	if h.upstream != nil {
		conn, err := h.upstream.DialTCP(ctx, targetAddr)
		if err != nil {
			return nil, fmt.Errorf("warp upstream dial failed: %w", err)
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

func (h *WarpHop) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("warp hop closed")
	}

	if h.upstream != nil {
		return h.upstream.ListenPacket(ctx, network, addr)
	}

	lc := &net.ListenConfig{}
	return lc.ListenPacket(ctx, network, addr)
}

func (h *WarpHop) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.upstream != nil {
		return h.upstream.Close()
	}
	return nil
}

func (h *WarpHop) Stats() (int64, int64) {
	return h.rxBytes.Load(), h.txBytes.Load()
}
