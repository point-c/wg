package wg

import (
	"errors"
	"github.com/point-c/wgapi/wgconfig"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"testing"
)

func TestOptionNop(t *testing.T) {
	o := &options{}
	err := OptionNop()(o)
	require.NoError(t, err)
}

func TestOptionErr(t *testing.T) {
	o := &options{}
	testError := errors.New("test error")
	err := OptionErr(testError)(o)
	require.Error(t, err)
	require.Equal(t, testError, err)
}

func TestOptionDevice(t *testing.T) {
	o := &options{}
	var n Netstack

	err := OptionDevice(&n)(o)
	require.NoError(t, err)
	require.Equal(t, &n, o.tun)

	err = OptionDevice(nil)(o)
	require.NoError(t, err)
}

func TestOptionBind(t *testing.T) {
	o := &options{}
	var b Bind

	err := OptionBind(b)(o)
	require.NoError(t, err)
	require.Equal(t, b, o.bind)

	err = OptionBind(nil)(o)
	require.NoError(t, err)
}

func TestOptionLogger(t *testing.T) {
	o := &options{}
	var l device.Logger

	err := OptionLogger(&l)(o)
	require.NoError(t, err)
	require.Contains(t, o.loggers, &l)

	err = OptionLogger(nil)(o)
	require.NoError(t, err)
}

func TestOptionConfig(t *testing.T) {
	o := &options{}
	cfg := wgconfig.Client{}

	err := OptionConfig(&cfg)(o)
	require.NoError(t, err)
	require.Equal(t, &cfg, *o.cfg)

	err = OptionConfig(nil)(o)
	require.NoError(t, err)
}

func TestOptionNetDevice(t *testing.T) {
	o := &options{}
	var p *Net

	err := OptionNetDevice(&p)(o)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, o.tun)
	require.Len(t, o.closer, 1)

	err = OptionNetDevice(nil)(o)
	require.Error(t, err)

	defer func(fn func(s *stack.Stack, ep *channel.Endpoint, id *tcpip.NICID) error) { SetStackOptions = fn }(SetStackOptions)
	errExp := errors.New("test")
	SetStackOptions = func(*stack.Stack, *channel.Endpoint, *tcpip.NICID) error { return errExp }
	err = OptionNetDevice(&p)(o)
	require.ErrorIs(t, err, errExp)
}

func TestOptionCloser(t *testing.T) {
	o := &options{}
	called := false
	closer := func() error {
		called = true
		return nil
	}

	err := OptionCloser(closer)(o)
	require.NoError(t, err)
	require.Len(t, o.closer, 1)

	_ = o.closer[0]()
	require.True(t, called)
}

func TestOptionsApply(t *testing.T) {
	o := &options{}
	opts := []Option{OptionNop(), OptionErr(errors.New("test error")), OptionNop()}

	err := o.apply(opts)
	require.Error(t, err)
}

func TestOptionsCleanUp(t *testing.T) {
	o := &options{}
	failed := true
	var err error

	o.cleanUp(&failed, &err)
	require.Nil(t, err)

	o.closer = append(o.closer, func() error { return errors.New("close error") })
	o.cleanUp(&failed, &err)
	require.Error(t, err)
	require.EqualError(t, err, "close error")
}
