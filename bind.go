package wg

import "golang.zx2c4.com/wireguard/conn"

type Bind = conn.Bind

// DefaultBind is the default wireguard UDP listener..
func DefaultBind() Bind {
	return conn.NewDefaultBind()
}
