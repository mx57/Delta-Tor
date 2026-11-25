package netcore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ChainConfig represents the JSON configuration received from Android/Kotlin or Windows.
type ChainConfig struct {
	Hops     []HopConfig `json:"hops"`
	BindPort int         `json:"bind_port,omitempty"` // 0 for auto-assign ephemeral port
	AuthUser string      `json:"auth_user,omitempty"`
	AuthPass string      `json:"auth_pass,omitempty"`
}

// HopConfig holds parameters for a single link in the chain.
type HopConfig struct {
	Type     string        `json:"type"` // "direct", "socks5", "awg", "warp", "masque"
	Socks5   *Socks5Config `json:"socks5,omitempty"`
	Awg      *AwgConfig    `json:"awg,omitempty"`
	Warp     *WarpConfig   `json:"warp,omitempty"`
	Masque   *MasqueConfig `json:"masque,omitempty"`
}

type Socks5Config struct {
	ProxyAddr string `json:"proxy_addr"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

// ChainHandle is the exported controller handle for the active chain.
type ChainHandle struct {
	hops        []HopDialer
	socksServer *SocksServer
	warpHop     *WarpHop
	mu          sync.Mutex
	closed      bool
}

// StartChain constructs and starts a multi-hop transport chain from a JSON configuration string.
func StartChain(jsonConfig string, protector SocketProtector) (*ChainHandle, error) {
	var cfg ChainConfig
	if err := json.Unmarshal([]byte(jsonConfig), &cfg); err != nil {
		return nil, fmt.Errorf("invalid chain config json: %w", err)
	}
	if len(cfg.Hops) == 0 {
		return nil, errors.New("chain must contain at least 1 hop")
	}
	if len(cfg.Hops) > 4 {
		return nil, errors.New("chain exceeds maximum of 4 hops")
	}

	var currentDialer HopDialer
	var hopsList []HopDialer
	var warpHop *WarpHop

	// Always begin with protected direct dialer at the base (Hop 0)
	baseDialer := NewProtectedDirectDialer(protector)
	currentDialer = baseDialer
	hopsList = append(hopsList, baseDialer)

	for i, h := range cfg.Hops {
		switch h.Type {
		case "direct":
			// Base dialer already handles direct
			continue
		case "socks5":
			if h.Socks5 == nil || h.Socks5.ProxyAddr == "" {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (socks5): missing proxy_addr", i)
			}
			s5 := NewSocks5HopDialer(currentDialer, h.Socks5.ProxyAddr, h.Socks5.Username, h.Socks5.Password)
			currentDialer = s5
			hopsList = append(hopsList, s5)
		case "awg":
			if h.Awg == nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (awg): missing awg config", i)
			}
			awg, err := NewAwgHop(currentDialer, *h.Awg)
			if err != nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (awg) failed: %w", i, err)
			}
			currentDialer = awg
			hopsList = append(hopsList, awg)
		case "warp":
			if h.Warp == nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (warp): missing warp config", i)
			}
			warp, err := NewWarpHop(currentDialer, *h.Warp)
			if err != nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (warp) failed: %w", i, err)
			}
			warpHop = warp
			currentDialer = warp
			hopsList = append(hopsList, warp)
		case "masque":
			if h.Masque == nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (masque): missing masque config", i)
			}
			masque, err := NewMasqueHop(currentDialer, *h.Masque)
			if err != nil {
				cleanupHops(hopsList)
				return nil, fmt.Errorf("hop %d (masque) failed: %w", i, err)
			}
			currentDialer = masque
			hopsList = append(hopsList, masque)
		default:
			cleanupHops(hopsList)
			return nil, fmt.Errorf("unknown hop type: %s", h.Type)
		}
	}

	// If no auth specified, generate CSPRNG one-time credentials for local isolation
	authUser := cfg.AuthUser
	authPass := cfg.AuthPass
	if authUser == "" {
		b := make([]byte, 16)
		rand.Read(b)
		authUser = "dt_" + hex.EncodeToString(b[:8])
		authPass = hex.EncodeToString(b[8:])
	}

	bindAddr := fmt.Sprintf("127.0.0.1:%d", cfg.BindPort)
	server, err := NewSocksServer(bindAddr, authUser, authPass, currentDialer)
	if err != nil {
		cleanupHops(hopsList)
		return nil, fmt.Errorf("failed to start egress socks server: %w", err)
	}

	return &ChainHandle{
		hops:        hopsList,
		socksServer: server,
		warpHop:     warpHop,
	}, nil
}

func cleanupHops(hops []HopDialer) {
	for i := len(hops) - 1; i >= 0; i-- {
		_ = hops[i].Close()
	}
}

// Stop terminates all links in the chain in reverse order (Exit -> ... -> Entry).
func (c *ChainHandle) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	var lastErr error
	if c.socksServer != nil {
		if err := c.socksServer.Close(); err != nil {
			lastErr = err
		}
	}

	for i := len(c.hops) - 1; i >= 0; i-- {
		if err := c.hops[i].Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// GetStats returns cumulative (rxBytes, txBytes) through the chain egress.
func (c *ChainHandle) GetStats() (int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.socksServer == nil {
		return 0, 0
	}
	return c.socksServer.Stats()
}

// GetSocksPort returns the local port bound by the egress SOCKS5 server.
func (c *ChainHandle) GetSocksPort() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.socksServer == nil {
		return 0
	}
	return c.socksServer.Port()
}

// RotateWarpEndpoint dynamically updates the WARP peer endpoint if a WARP hop is active.
func (c *ChainHandle) RotateWarpEndpoint(newEndpoint string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.warpHop == nil {
		return errors.New("no active warp hop in chain")
	}
	return c.warpHop.RotateEndpoint(newEndpoint)
}
