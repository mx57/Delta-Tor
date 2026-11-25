package netcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type mockProtector struct {
	protectedCount int
}

func (m *mockProtector) Protect(fd int) bool {
	m.protectedCount++
	return true
}

type echoServer struct {
	ln net.Listener
}

func startEchoServer(t *testing.T) *echoServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	s := &echoServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return s
}

func (s *echoServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *echoServer) Close() {
	s.ln.Close()
}

func TestSocksServerAuthAndRelay(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	protector := &mockProtector{}
	direct := NewProtectedDirectDialer(protector)

	user := "testuser"
	pass := "secretpass123"

	server, err := NewSocksServer("127.0.0.1:0", user, pass, direct)
	if err != nil {
		t.Fatalf("failed to start socks server: %v", err)
	}
	defer server.Close()

	// 1. Test rejected auth
	badDialer := NewSocks5HopDialer(direct, server.Addr(), user, "wrongpass")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = badDialer.DialTCP(ctx, echo.Addr())
	if err == nil {
		t.Fatalf("expected auth error with bad password, got success")
	}

	// 2. Test successful auth and data transmission
	goodDialer := NewSocks5HopDialer(direct, server.Addr(), user, pass)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	conn, err := goodDialer.DialTCP(ctx2, echo.Addr())
	if err != nil {
		t.Fatalf("goodDialer failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("Hello DeltaTor SOCKS5!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %s, got %s", string(msg), string(buf))
	}

	rx, tx := server.Stats()
	if rx == 0 || tx == 0 {
		t.Fatalf("expected non-zero server stats, got rx=%d, tx=%d", rx, tx)
	}
}

func TestUoTAdapterFraming(t *testing.T) {
	// Create an in-memory pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	adapter := NewUoTAdapter(clientConn)

	targetAddr, err := net.ResolveUDPAddr("udp", "198.51.100.1:5353")
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	payload := []byte("dns query payload")

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Server side parses UoT frame
		serverAdapter := NewUoTAdapter(serverConn)
		buf := make([]byte, 1024)
		n, addr, err := serverAdapter.ReadFrom(buf)
		if err != nil {
			t.Errorf("server read error: %v", err)
			return
		}
		if n != len(payload) {
			t.Errorf("expected len %d, got %d", len(payload), n)
		}
		if string(buf[:n]) != string(payload) {
			t.Errorf("expected payload %s, got %s", string(payload), string(buf[:n]))
		}
		if addr.String() != targetAddr.String() {
			t.Errorf("expected addr %s, got %s", targetAddr.String(), addr.String())
		}
	}()

	n, err := adapter.WriteTo(payload, targetAddr)
	if err != nil {
		t.Fatalf("adapter write error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("written byte count mismatch: %d vs %d", n, len(payload))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for uot framing test")
	}
}

func TestStartChainMultiHop(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	protector := &mockProtector{}

	configJSON := fmt.Sprintf(`{
		"hops": [
			{ "type": "direct" },
			{
				"type": "awg",
				"awg": {
					"private_key": "dummy_priv",
					"address": "10.0.0.2/32",
					"peer_public_key": "dummy_pub",
					"endpoint": "127.0.0.1:51820",
					"mtu": 1280,
					"jc": 3,
					"jmin": 10,
					"jmax": 20
				}
			},
			{
				"type": "warp",
				"warp": {
					"private_key": "warp_priv",
					"peer_public_key": "warp_pub",
					"endpoint": "162.159.192.1:2408",
					"reserved": [1, 2, 3],
					"mtu": 1280
				}
			}
		],
		"bind_port": 0,
		"auth_user": "u1",
		"auth_pass": "p1"
	}`)

	chain, err := StartChain(configJSON, protector)
	if err != nil {
		t.Fatalf("StartChain failed: %v", err)
	}
	defer chain.Stop()

	port := chain.GetSocksPort()
	if port <= 0 {
		t.Fatalf("invalid socks port: %d", port)
	}

	// Test endpoint rotation on WARP hop
	err = chain.RotateWarpEndpoint("162.159.193.1:2408")
	if err != nil {
		t.Fatalf("RotateWarpEndpoint failed: %v", err)
	}

	// Test connecting through the chain's egress SOCKS5 proxy
	dialer := NewSocks5HopDialer(nil, fmt.Sprintf("127.0.0.1:%d", port), "u1", "p1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTCP(ctx, echo.Addr())
	if err != nil {
		t.Fatalf("dial through chain egress failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	res := make([]byte, 4)
	if _, err := io.ReadFull(conn, res); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(res) != "ping" {
		t.Fatalf("expected ping, got %s", string(res))
	}
}
