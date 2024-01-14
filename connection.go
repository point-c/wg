// Package wg helps with the creation and usage of userland wireguard networks.
package wg

import (
	"errors"
	"github.com/point-c/wgapi"
	"github.com/point-c/wglog"
	"golang.zx2c4.com/wireguard/device"
	"sync/atomic"
)

// Wireguard handles configuring and closing a wireguard client/server.
type Wireguard struct {
	dev     *device.Device
	close   atomic.Pointer[error]
	closers []func() error
}

var (
	ErrNoDeviceSpecified = errors.New("no device specified")
)

// New allows the creating of a new wireguard interface.
func New(opts ...Option) (_ *Wireguard, err error) {
	var o options
	if err = o.apply(opts); err != nil {
		return nil, err
	}

	failed := true
	defer o.cleanUp(&failed, &err)

	if o.tun == nil {
		return nil, ErrNoDeviceSpecified
	}

	if o.bind == nil {
		o.bind = DefaultBind()
		o.closer = append(o.closer, o.bind.Close)
	}

	c := &Wireguard{dev: device.NewDevice(o.tun, o.bind, wglog.Multi(o.loggers...))}
	defer func() { c.closers = o.closer }()
	o.closer = append(o.closer, func() error { c.dev.Close(); return nil })

	if o.cfg != nil {
		if err := c.SetConfig(*o.cfg); err != nil {
			return nil, err
		}
	}

	if err := c.dev.Up(); err != nil {
		return nil, err
	}
	o.closer = append(o.closer, c.dev.Down)

	failed = false
	return c, nil
}

// GetConfig gets the raw config from an IPC get=1 operation.
func (c *Wireguard) GetConfig() (v wgapi.IPC, err error) {
	var ipc wgapi.IPCGet
	if err = c.dev.IpcGetOperation(&ipc); err == nil {
		v, err = ipc.Value()
	}
	return
}

// SetConfig performs an IPC set=1 operation.
func (c *Wireguard) SetConfig(cfg wgapi.Configurable) error {
	return c.dev.IpcSetOperation(cfg.WGConfig())
}

// Close closes the wireguard server/client, rendering it unusable in the future.
func (c *Wireguard) Close() (err error) {
	if c.close.CompareAndSwap(nil, &err) {
		for i := len(c.closers) - 1; i >= 0; i-- {
			err = errors.Join(err, c.closers[i]())
		}
		c.closers = nil
	}
	return *c.close.Load()
}
