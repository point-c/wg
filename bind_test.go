package wg

import (
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn"
	"testing"
)

func TestDefaultBind(t *testing.T) {
	require.IsType(t, conn.NewDefaultBind(), DefaultBind())
}
