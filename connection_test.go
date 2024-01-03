package wg_test

import (
	"context"
	"github.com/point-c/wg"
	"github.com/point-c/wgapi"
	"github.com/point-c/wgapi/wgconfig"
	"github.com/point-c/wglog"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"math"
	"net"
	"testing"
	"time"
)

const logWG = false

func TestTCPConnection(t *testing.T) {
	pair := netPair(t)
	require.NotNil(t, pair)
	defer pair.Closer()
	remoteAddrChan := make(chan net.IP)

	rand.Seed(uint64(time.Now().UnixMicro()))
	rand8 := func() uint8 { return uint8(rand.Intn(math.MaxUint8) + 1) }
	remoteAddr := net.IPv4(rand8(), rand8(), rand8(), 1)
	remotePort := uint16(rand8() * rand8())

	ln, err := pair.Client.Listen(&net.TCPAddr{IP: pair.ClientIP, Port: int(remotePort)})
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		defer close(remoteAddrChan)
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		remoteAddrChan <- c.RemoteAddr().(*net.TCPAddr).IP
	}()

	ctx, cancel := textCtxDeadline(t, context.Background())
	defer cancel()
	stop := context.AfterFunc(ctx, func() { t.Log("dialer timeout") })

	c, err := pair.Server.Dialer(remoteAddr, 0).DialTCP(ctx, &net.TCPAddr{IP: pair.ClientIP, Port: int(remotePort)})
	ok := stop()
	require.NoError(t, err)
	defer c.Close()
	require.True(t, ok)

	ctx, cancel = textCtxDeadline(t, context.Background())
	defer cancel()
	select {
	case addr, ok := <-remoteAddrChan:
		require.True(t, ok)
		require.Truef(t, remoteAddr.Equal(addr), "remote(%s) != addr(%s)", remoteAddr.String(), addr.String())
		t.Logf("got remote ip %s", addr)
	case <-ctx.Done():
		t.Error("timeout")
	}
}

func textCtxDeadline(t *testing.T, ctx context.Context) (context.Context, context.CancelFunc) {
	t.Helper()
	if d, ok := t.Deadline(); ok {
		return context.WithDeadline(ctx, d)
	}
	return context.WithDeadline(ctx, time.Now().Add(time.Second*10))
}

type NetPair struct {
	Client       *wg.Net
	ClientCloser func()
	ClientIP     net.IP
	Server       *wg.Net
	ServerCloser func()
	t            testing.TB
	Bindcloser   func()
}

func (np *NetPair) Closer() {
	np.t.Helper()
	defer np.Bindcloser()
	defer np.ClientCloser()
	defer np.ServerCloser()
}

func netPair(t testing.TB) *NetPair {
	t.Helper()
	pair := NetPair{t: t}
	pair.ClientIP = net.IPv4(192, 168, 123, 2)
	clientConfig, serverConfig, err := wgconfig.GenerateConfigPair(&net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1}, pair.ClientIP)
	if err != nil {
		t.Log(err)
		t.Fail()
		return nil
	}

	binds := bindtest.NewChannelBinds()
	pair.Bindcloser = func() {
		defer binds[0].Close()
		defer binds[1].Close()
	}

	pair.Client, pair.ClientCloser = GetNet(t, binds[0], clientConfig)
	pair.Server, pair.ServerCloser = GetNet(t, binds[1], serverConfig)
	if pair.Client == nil || pair.Server == nil {
		pair.Bindcloser()
		if pair.Client != nil {
			pair.ClientCloser()
		}
		if pair.Server != nil {
			pair.ServerCloser()
		}
		return nil
	}
	return &pair
}

func GetNet(t testing.TB, bind conn.Bind, cfg wgapi.Configurable) (*wg.Net, func()) {
	t.Helper()
	logger := wglog.Noop()
	if logWG {
		logger = testLogger(t)
	}

	var n *wg.Net
	c, err := wg.New(wg.OptionNetDevice(&n), wg.OptionBind(bind), wg.OptionConfig(cfg), wg.OptionLogger(logger))
	if err != nil {
		t.Log(err)
		t.Fail()
		return nil, nil
	}

	return n, func() {
		t.Helper()
		if err := c.Close(); err != nil {
			t.Log(err)
			t.Fail()
		}
	}
}

func testLogger(t testing.TB) *device.Logger {
	t.Helper()
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			t.Helper()
			t.Logf("ERROR: "+format, args...)
		},
		Errorf: func(format string, args ...any) {
			t.Helper()
			t.Logf("INFO:  "+format, args...)
		},
	}
}
