package wg

import (
	"context"
	"errors"
	"github.com/point-c/wgapi"
	"github.com/point-c/wgapi/wgconfig"
	"github.com/point-c/wglog"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"io"
	"math"
	"net"
	"slices"
	"strings"
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
	Client       *Net
	ClientCloser func()
	ClientIP     net.IP
	Server       *Net
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

func GetNet(t testing.TB, bind conn.Bind, cfg wgapi.Configurable) (*Net, func()) {
	t.Helper()
	logger := wglog.Noop()
	if logWG {
		logger = testLogger(t)
	}

	var n *Net
	c, err := New(OptionNetDevice(&n), OptionBind(bind), OptionConfig(cfg), OptionLogger(logger))
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

func TestNew(t *testing.T) {
	bind := DefaultBind
	t.Cleanup(func() { DefaultBind = bind })
	DefaultBind = func() Bind {
		return bindtest.NewChannelBinds()[0]
	}

	t.Run("error applying options", func(t *testing.T) {
		errExp := errors.New("test")
		v, err := New(OptionErr(errExp))
		require.ErrorIs(t, err, errExp)
		require.Nil(t, v)
	})

	t.Run("no tun", func(t *testing.T) {
		v, err := New()
		require.ErrorIs(t, err, ErrNoDeviceSpecified)
		require.Nil(t, v)
	})

	t.Run("use default bind", func(t *testing.T) {
		var n *Net
		v, err := New(
			OptionNetDevice(&n),
		)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.NoError(t, v.Close())
	})

	t.Run("set config", func(t *testing.T) {
		var n *Net
		v, err := New(
			OptionNetDevice(&n),
			OptionConfig(wgapi.IPC{}),
		)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.NoError(t, v.Close())
	})

	t.Run("bad set config", func(t *testing.T) {
		var n *Net
		v, err := New(
			OptionNetDevice(&n),
			OptionConfig(testErrConfig{t}),
		)
		require.Error(t, err)
		require.Nil(t, v)
	})

	t.Run("bad up", func(t *testing.T) {
		var n *Net
		b := testErrBadBindOpen{
			TB:  t,
			err: errors.New("test"),
		}
		v, err := New(
			OptionNetDevice(&n),
			OptionBind(b),
		)
		require.ErrorIs(t, err, b.err)
		require.Nil(t, v)
	})
}

type testErrBadBindOpen struct {
	testing.TB
	err error
}

func (t testErrBadBindOpen) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	t.Helper()
	return nil, port, t.err
}
func (t testErrBadBindOpen) Close() error                       { t.Helper(); return nil }
func (t testErrBadBindOpen) SetMark(uint32) error               { t.Helper(); panic("not implemented") }
func (t testErrBadBindOpen) Send([][]byte, conn.Endpoint) error { t.Helper(); panic("not implemented") }
func (t testErrBadBindOpen) ParseEndpoint(string) (conn.Endpoint, error) {
	t.Helper()
	panic("not implemented")
}
func (t testErrBadBindOpen) BatchSize() int { return 0 }

type testErrConfig struct{ testing.TB }

func (t testErrConfig) WGConfig() io.Reader {
	t.Helper()
	return strings.NewReader(`foo=bar
`)
}

func TestGetConfig(t *testing.T) {
	bind := DefaultBind
	t.Cleanup(func() { DefaultBind = bind })
	testBind := bindtest.NewChannelBinds()[0]
	DefaultBind = func() Bind {
		return testBind
	}
	var n *Net

	cfgExp := wgapi.IPC{wgapi.ListenPort(4)}
	v, err := New(
		OptionNetDevice(&n),
		OptionConfig(cfgExp),
	)
	require.NoError(t, err)
	require.NotNil(t, v)
	cfg, err := v.GetConfig()
	require.NoError(t, err)
	require.Len(t, cfg, 1)
	p := cfg[0]
	require.IsType(t, wgapi.ListenPort(0), p)
	require.True(t, slices.Contains([]wgapi.ListenPort{2, 4}, p.(wgapi.ListenPort)))
}
