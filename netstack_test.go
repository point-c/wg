package wg

import (
	"context"
	"errors"
	"github.com/point-c/ipcheck"
	"github.com/point-c/simplewg"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"math"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	testLocalIP    = net.IPv4(192, 168, 0, 1)
	testRemoteIP   = net.IPv4(192, 168, 0, 1)
	testLoopbackIP = net.IPv4(127, 0, 0, 1)
)

func TestStackOptions(t *testing.T) {
	t.Run("error on sack enable", func(t *testing.T) {
		err := SetStackOptions(stack.New(stack.Options{}), nil, nil)
		require.ErrorContains(t, err, "unknown protocol")
	})
	t.Run("error on nic add", func(t *testing.T) {
		s := stack.New(stack.Options{
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
		id := tcpip.NICID(int32(1))
		s.CreateNIC(id, channel.New(1, uint32(1500), ""))
		err := SetStackOptions(s, channel.New(1, uint32(1500), ""), &id)
		require.ErrorContains(t, err, "duplicate nic id")
	})
}

func TestTCPIPError(t *testing.T) {
	e := &tcpip.ErrAborted{}
	err := TCPIPError{Err: e}
	require.ErrorContains(t, &err, e.String())
}

func TestWriteNotify(t *testing.T) {
	t.Run("nil packet", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()
		wn := (*writeNotify)(netstack)
		wn.WriteNotify()
	})
	t.Run("read", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		closeOnce := sync.OnceFunc(func() { require.NoError(t, netstack.Close()) })
		defer closeOnce()
		var testPackets stack.PacketBufferList
		testPackets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{4 << 4})}))
		errs := make(chan error)
		go func() {
			defer close(errs)
			i, err := netstack.ep.WritePackets(testPackets)
			if i != 1 {
				errs <- errors.New("packet not written")
			} else if err != nil {
				errs <- &TCPIPError{Err: err}
			}
		}()
		_, err = netstack.Read([][]byte{{}}, []int{0}, 0)
		require.NoError(t, err)
		require.NoError(t, <-errs)
	})
	t.Run("read closed", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()
		errs := make(chan error)
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()
		go func(ctx context.Context) {
			defer cancel()
			defer close(errs)
			var testPackets stack.PacketBufferList
			testPackets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{4 << 4})}))
			i, e := netstack.ep.WritePackets(testPackets)
			var err error
			if i != 1 {
				err = errors.New("packet not written")
			} else if err != nil {
				err = &TCPIPError{Err: e}
			}
			select {
			case <-ctx.Done():
			case errs <- err:
			}
		}(ctx)
		ctx, cancel = context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		select {
		case <-ctx.Done():
			require.NoError(t, netstack.Close())
			require.NoError(t, <-errs)
		}
	})
}

func TestNewDefaultNetstack(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	require.NotNil(t, netstack)
	require.Equal(t, DefaultMTU, netstack.mtu)
	require.Equal(t, DefaultBatchSize, netstack.batchSize)
}

func TestNewNetstack(t *testing.T) {
	mtu := 1400
	batchSize := 10
	channelSize := 50

	netstack, err := NewNetstack(mtu, batchSize, channelSize)
	require.NoError(t, err)
	defer netstack.Close()
	require.NotNil(t, netstack)
	require.Equal(t, mtu, netstack.mtu)
	require.Equal(t, batchSize, netstack.batchSize)
}

func TestNetstackClose(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	require.NoError(t, netstack.Close())
}

func TestNetstackFile(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	require.Nil(t, netstack.File())
}

func TestNetstackName(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	name, err := netstack.Name()
	require.NoError(t, err)
	require.Equal(t, "point-c", name)
}

func TestNetstackReadAndWrite(t *testing.T) {
	t.Run("write ipv4", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()

		_, err = netstack.Write([][]byte{{4 << 4}}, 0)
		require.NoError(t, err)
	})

	t.Run("write empty bufs", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()

		_, err = netstack.Write([][]byte{nil, nil}, 0)
		require.NoError(t, err)
	})

	t.Run("write ipv6", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()

		_, err = netstack.Write([][]byte{{6 << 4}}, 0)
		require.NoError(t, err)
	})

	t.Run("read packet", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()

		go func() { netstack.read <- []byte{} }()
		_, err = netstack.Read([][]byte{{}}, []int{0}, 0)
		require.NoError(t, err)
	})

	t.Run("read closed", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		require.NoError(t, netstack.Close())
		_, err = netstack.Read([][]byte{{}}, []int{0}, 0)
		require.Error(t, err)
	})
}

func TestNetstackListen(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	n := netstack.Net()
	listener, err := n.Listen(&net.TCPAddr{IP: testLocalIP, Port: 8080})
	require.NoError(t, err)
	require.NotNil(t, listener)
	_, err = n.Listen(&net.TCPAddr{IP: testLoopbackIP})
	require.ErrorIs(t, err, ipcheck.ErrInvalidLocalIP)
}

func TestNetstackListenPacket(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	n := netstack.Net()
	packetConn, err := n.ListenPacket(&net.UDPAddr{IP: testLocalIP, Port: 8080})
	require.NoError(t, err)
	require.NotNil(t, packetConn)
	_, err = n.ListenPacket(&net.UDPAddr{IP: testLoopbackIP})
	require.ErrorIs(t, err, ipcheck.ErrInvalidLocalIP)
}

func TestDialerDialTCP(t *testing.T) {
	t.Run("context cancelled", func(t *testing.T) {
		netstack, err := NewDefaultNetstack()
		require.NoError(t, err)
		defer netstack.Close()
		n := netstack.Net()
		dialer := n.Dialer(testLocalIP, 8081)
		ctx, cancel := context.WithCancel(context.TODO())
		cancel()
		conn, err := dialer.DialTCP(ctx, &net.TCPAddr{IP: testLocalIP, Port: 8080})
		require.Error(t, err)
		require.Nil(t, conn)
	})

	tests := []struct {
		name   string
		listen net.IP
		local  net.IP
		remote net.IP
		err    error
	}{
		{
			name:   "basic",
			listen: testRemoteIP,
			remote: testRemoteIP,
			local:  testLocalIP,
		},
		{
			name:   "listen 0.0.0.0",
			listen: net.IPv4zero,
			remote: testRemoteIP,
			local:  testLocalIP,
		},
		{
			name:   "invalid local",
			listen: testRemoteIP,
			remote: testRemoteIP,
			local:  testLoopbackIP,
			err:    ipcheck.ErrInvalidLocalIP,
		},
		{
			name:   "invalid remote",
			listen: testRemoteIP,
			remote: testLoopbackIP,
			local:  testLocalIP,
			err:    ipcheck.ErrInvalidRemoteIP,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var w simplewg.Wg
			defer w.Wait()
			netstack1, err := NewDefaultNetstack()
			require.NoError(t, err)
			defer netstack1.Close()
			n1 := netstack1.Net()
			netstack2, err := NewDefaultNetstack()
			require.NoError(t, err)
			defer netstack2.Close()
			n2 := netstack2.Net()

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()
			if dl, ok := t.Deadline(); ok {
				ctx, cancel = context.WithDeadline(ctx, dl)
			} else {
				if err != nil {
					ctx, cancel = context.WithTimeout(ctx, time.Second*2)
				} else {
					ctx, cancel = context.WithTimeout(ctx, time.Second*5)
				}
			}
			defer cancel()

			done := make(chan struct{})
			if tt.err != nil {
				close(done)
			} else {
				copyNetstack := func(net1, net2 *Netstack) {
					for {
						b := [][]byte{make([]byte, math.MaxUint16)}
						s := []int{0}
						n, err := net1.Read(b, s, 0)
						if err != nil {
							return
						} else if n == 0 {
							continue
						}
						_, err = net2.Write(b, 0)
						if err != nil {
							t.Error(err.Error())
						}
					}
				}
				w.Go(func() { copyNetstack(netstack1, netstack2) })
				w.Go(func() { copyNetstack(netstack2, netstack1) })
				go func() {
					defer close(done)
					defer cancel()
					ln, err := n1.Listen(&net.TCPAddr{IP: tt.listen, Port: 123})
					require.NoError(t, err)
					cn, err := ln.Accept()
					require.NoError(t, err)
					require.NotNil(t, cn)
				}()
			}

			cn, err := n2.Dialer(tt.local, 0).DialTCP(ctx, &net.TCPAddr{IP: tt.remote, Port: 123})
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				require.Nil(t, cn)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cn)
				require.NoError(t, cn.Close())
			}
			<-done
		})
	}
}

func TestDialerDialUDP(t *testing.T) {
	netstack, err := NewDefaultNetstack()
	require.NoError(t, err)
	defer netstack.Close()
	n := netstack.Net()
	dialer := n.Dialer(testLocalIP, 8080)
	packetConn, err := dialer.DialUDP(&net.UDPAddr{IP: testLocalIP, Port: 8081})
	require.NoError(t, err)
	require.NotNil(t, packetConn)
	_, err = n.Dialer(testLocalIP, 0).DialUDP(&net.UDPAddr{IP: testLoopbackIP})
	require.ErrorIs(t, err, ipcheck.ErrInvalidRemoteIP)
	_, err = n.Dialer(testLoopbackIP, 0).DialUDP(&net.UDPAddr{IP: testLocalIP})
	require.ErrorIs(t, err, ipcheck.ErrInvalidLocalIP)
}
