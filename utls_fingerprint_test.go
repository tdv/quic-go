package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/testdata"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

const extCompressCertificate = 27

func observedClientHello(t *testing.T, serverName string, conf *Config) *tls.ClientHelloInfo {
	t.Helper()
	hellos := make(chan *tls.ClientHelloInfo, 1)
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"utls-test"}
	serverTLS.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case hellos <- h:
		default:
		}
		return nil, nil
	}
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, err := ln.Accept(context.Background())
		if err == nil {
			<-c.Context().Done()
		}
	}()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &Transport{Conn: udp}
	defer func() {
		tr.Close()
		udp.Close()
		ln.Close()
		<-accepted
		require.Eventually(t, func() bool { return !areConnsRunning() && !areTransportsRunning() }, 5*time.Second, 10*time.Millisecond)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientTLS := &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: serverName, NextProtos: []string{"utls-test"}}
	if serverName == "" {
		clientTLS = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"utls-test"}}
	}
	conn, err := tr.Dial(ctx, ln.Addr(), clientTLS, conf)
	require.NoError(t, err)
	conn.CloseWithError(0, "")

	select {
	case h := <-hellos:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw a ClientHello")
		return nil
	}
}

func TestTransportDialAppliesUTLSClientHello(t *testing.T) {
	chrome := utls.HelloChrome_Auto
	h := observedClientHello(t, "localhost", &Config{ClientHelloID: &chrome})
	require.True(t, slices.Contains(h.Extensions, extCompressCertificate),
		"ClientHelloID was not applied: no Chrome compress_certificate extension in %v", h.Extensions)

	byIP := observedClientHello(t, "", &Config{ClientHelloID: &chrome})
	require.True(t, slices.Contains(byIP.Extensions, extCompressCertificate),
		"dialing an IP (no SNI, GREASE ECH only) must still complete with the uTLS hello")

	plain := observedClientHello(t, "localhost", nil)
	require.False(t, slices.Contains(plain.Extensions, extCompressCertificate),
		"without ClientHelloID the standard crypto/tls hello must be used")
}

func TestPopulateConfigKeepsForkFields(t *testing.T) {
	chrome := utls.HelloChrome_Auto
	c := populateConfig(&Config{ClientHelloID: &chrome, ActiveConnectionIDLimit: 8, DisableActiveMigration: true})
	require.Equal(t, &chrome, c.ClientHelloID)
	require.Equal(t, uint64(8), c.ActiveConnectionIDLimit)
	require.True(t, c.DisableActiveMigration)
}

func TestClientAcceptsConnectionIDsUpToAdvertisedLimit(t *testing.T) {
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"cid-test"}
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := c.AcceptStream(context.Background())
		if err == nil {
			buf := make([]byte, 4)
			if _, err := str.Read(buf); err == nil {
				str.Write(buf)
			}
		}
		<-c.Context().Done()
	}()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &Transport{Conn: udp}
	defer func() {
		tr.Close()
		udp.Close()
		ln.Close()
		<-served
		require.Eventually(t, func() bool { return !areConnsRunning() && !areTransportsRunning() }, 5*time.Second, 10*time.Millisecond)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientTLS := &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: []string{"cid-test"}}
	conn, err := tr.Dial(ctx, ln.Addr(), clientTLS, &Config{ActiveConnectionIDLimit: 8})
	require.NoError(t, err)
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(str, buf)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, conn.Context().Err(), "connection closed after the server issued connection IDs within our advertised limit")
	conn.CloseWithError(0, "")
}
