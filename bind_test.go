package wg

import (
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn"
	"testing"
)

func TestDefaultBind(t *testing.T) {
	exp := conn.NewDefaultBind()
	defer exp.Close()
	got := DefaultBind()
	defer got.Close()
	require.IsType(t, exp, got)
}
