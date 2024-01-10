package wg

import "golang.zx2c4.com/wireguard/conn"

type Bind = conn.Bind

var DefaultBind = defaultBind

// DefaultBind is the default wireguard UDP listener.
func defaultBind() Bind {
	return conn.NewDefaultBind()
}
