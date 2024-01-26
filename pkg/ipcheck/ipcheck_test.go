package ipcheck

import (
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

var (
	testLocalIP    = net.IPv4(192, 168, 0, 1)
	testRemoteIP   = net.IPv4(192, 168, 0, 1)
	testLoopbackIP = net.IPv4(127, 0, 0, 1)
)

func TestIsBogon(t *testing.T) {
	tests := []struct {
		name string
		args net.IP
		want bool
	}{
		{
			name: "loopback",
			args: testLoopbackIP,
			want: true,
		},
		{
			name: "private",
			args: testRemoteIP,
		},
		{
			name: "IPv4bcast",
			args: net.IPv4bcast,
			want: true,
		},
		{
			name: "IPv4allrouter",
			args: net.IPv4allrouter,
			want: true,
		},
		{
			name: "IPv4allsys",
			args: net.IPv4allsys,
			want: true,
		},
		{
			name: "linklocal",
			args: net.IPv4(169, 254, 1, 1),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWantFn(t, tt.want)(t, IsBogon(tt.args))
		})
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		name string
		args net.IP
		want bool
	}{
		{
			name: "ok",
			args: net.IPv4(169, 254, 1, 1),
			want: true,
		},
		{
			name: "fail",
			args: testLocalIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWantFn(t, tt.want)(t, IsLinkLocal(tt.args))
		})
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		name string
		args net.IP
		want bool
	}{
		{
			name: "loopback",
			args: testLoopbackIP,
			want: true,
		},
		{
			name: "private",
			args: testRemoteIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWantFn(t, tt.want)(t, IsLoopback(tt.args))
		})
	}
}

func TestIsPrivateNetwork(t *testing.T) {
	tests := []struct {
		name string
		args net.IP
		want bool
	}{
		{
			name: "loopback",
			args: testLoopbackIP,
		},
		{
			name: "private",
			args: testRemoteIP,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWantFn(t, tt.want)(t, IsPrivateNetwork(tt.args))
		})
	}
}

func testWantFn(t testing.TB, want bool) func(require.TestingT, bool, ...any) {
	if want {
		return require.True
	}
	return require.False
}
