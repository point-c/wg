package wg

import (
	"context"
	"errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"net"
	"os"
	"slices"
	"sync"
)

const (
	// WireguardHeaderSize is the size of a wireguard header. The MTU needed for the [Netstack] is <actual hardware MTU> - [WireguardHeaderSize].
	WireguardHeaderSize = 80
	// DefaultMTU is the default MTU as specified from wireguard-go
	DefaultMTU = device.DefaultMTU
	// DefaultBatchSize is the default number of packets read/written from the [tun.Device] in one operation.
	DefaultBatchSize = conn.IdealBatchSize
	// DefaultChannelSize is the size of the packet queue for the underlaying [channel.Endpoint]
	DefaultChannelSize = 8 * DefaultBatchSize
)

var _ Device = (*Netstack)(nil)

// Netstack is a wireguard device that takes the raw packets communicated through wireguard and turns them into meaningful TCP/UDP connections.
type Netstack struct {
	ep         *channel.Endpoint
	stack      *stack.Stack
	events     chan tun.Event
	batchSize  int
	close      sync.Once
	done       chan struct{}
	read       chan []byte
	defaultNIC tcpip.NICID
	mtu        int
}

type Device = tun.Device

// NewDefaultNetstack calls NewNetstack with the default values.
func NewDefaultNetstack() (*Netstack, error) {
	return NewNetstack(DefaultMTU, DefaultBatchSize, DefaultChannelSize)
}

// NewNetstack creates a new wireguard network stack.
func NewNetstack(mtu int, batchSize int, channelSize int) (*Netstack, error) {
	d := &Netstack{
		mtu: mtu,
		// Packet ingress/egress
		ep: channel.New(channelSize, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
				arp.NewProtocol}, // TODO: is this needed?
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6},
			HandleLocal: false, // TODO: is this needed?
		}),
		events:    make(chan tun.Event, 1),
		batchSize: batchSize,
		done:      make(chan struct{}),
		read:      make(chan []byte),
	}
	d.ep.AddNotify((*writeNotify)(d))

	if err := SetStackOptions(d.stack, d.ep, &d.defaultNIC); err != nil {
		return nil, err
	}

	// Important! This allows us to remote/local on whatever address we want!
	d.stack.SetSpoofing(d.defaultNIC, true)
	d.stack.SetPromiscuousMode(d.defaultNIC, true)

	// Route all packets out of stack
	d.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: d.defaultNIC})
	d.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: d.defaultNIC})

	d.events <- tun.EventUp
	return d, nil
}

var SetStackOptions = func(s *stack.Stack, ep *channel.Endpoint, id *tcpip.NICID) error {
	// Wireguard-go does this
	var enableSACK tcpip.TCPSACKEnabled = true
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &enableSACK); err != nil {
		return &TCPIPError{Err: err}
	}

	// Add the endpoint to the stack
	*id = tcpip.NICID(s.UniqueID())
	if err := s.CreateNICWithOptions(*id, ep, stack.NICOptions{Name: ""}); err != nil {
		return &TCPIPError{Err: err}
	}
	return nil
}

// Close closes the network stack rendering it unusable in the future.
func (d *Netstack) Close() error {
	d.close.Do(func() {
		close(d.done)
		go func() { d.events <- tun.EventDown }()
		d.ep.Close()
		d.ep.Wait()
	})
	return nil
}

var _ channel.Notification = (*writeNotify)(nil)

type writeNotify Netstack

func (w *writeNotify) WriteNotify() {
	pkt := w.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := slices.Clone(pkt.ToView().AsSlice())
	pkt.DecRef()
	select {
	case <-w.done:
	case w.read <- view:
	}
}

// File implements [tun.Device.File] and always returns nil
func (d *Netstack) File() *os.File { return nil }

// Name implements [tun.Device.Name] and always returns "point-c"
func (d *Netstack) Name() (string, error) { return "point-c", nil }

// MTU implements [tun.Device.MTU] and returns the configured MTU
func (d *Netstack) MTU() (int, error) { return d.mtu, nil }

// Events implements [tun.Device.Events]
func (d *Netstack) Events() <-chan tun.Event { return d.events }

// BatchSize implements [tun.Device.BatchSize] and returns the configured BatchSize
func (d *Netstack) BatchSize() int { return d.batchSize }

// Read will always read exactly one packet at a time.
func (d *Netstack) Read(buf [][]byte, sizes []int, offset int) (n int, err error) {
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case p := <-d.read:
		sizes[0] = copy(buf[0][offset:], p)
		return 1, nil
	}
}

// Write will write all packets given to it to the underlaying netstack.
func (d *Netstack) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		buf = buf[offset:]
		if len(buf) == 0 {
			continue
		}

		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
		switch buf[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, packet)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, packet)
		}
	}
	return len(buf), nil
}

// TCPIPError turn a [tcpip.Error] into a normal error.
type TCPIPError struct{ Err tcpip.Error }

func (err *TCPIPError) Error() string { return err.Err.String() }

// Net handles the application level dialing/listening.
type Net Netstack

var _ interface {
	Listen(*net.TCPAddr) (net.Listener, error)
	ListenPacket(*net.UDPAddr) (net.PacketConn, error)
	Dialer(net.IP, uint16) *Dialer
} = (*Net)(nil)

var _ interface {
	DialTCP(context.Context, *net.TCPAddr) (net.Conn, error)
	DialUDP(*net.UDPAddr) (net.PacketConn, error)
} = (*Dialer)(nil)

// Dialer handles dialing with a given local address
type Dialer struct {
	net   *Net
	laddr tcpip.FullAddress
}

// Net allows using the device similar to the [net] package.
func (d *Netstack) Net() *Net { return (*Net)(d) }

// Listen listens with the TCP protocol on the given address.
func (n *Net) Listen(addr *net.TCPAddr) (net.Listener, error) {
	if IsBogon(addr.IP) {
		return nil, ErrInvalidLocalIP
	}

	return gonet.ListenTCP(n.stack, tcpip.FullAddress{
		NIC:  n.defaultNIC,
		Addr: tcpip.AddrFromSlice(addr.IP),
		Port: uint16(addr.Port),
	}, ipv4.ProtocolNumber)
}

// ListenPacket listens with the UDP protocol on the given address
func (n *Net) ListenPacket(addr *net.UDPAddr) (net.PacketConn, error) {
	if IsBogon(addr.IP) {
		return nil, ErrInvalidLocalIP
	}

	return gonet.DialUDP(n.stack, &tcpip.FullAddress{
		NIC:  n.defaultNIC,
		Addr: tcpip.AddrFromSlice(addr.IP),
		Port: uint16(addr.Port),
	}, nil, ipv4.ProtocolNumber)
}

// Dialer creates a new dialer with a specified local address.
func (n *Net) Dialer(laddr net.IP, port uint16) *Dialer {
	return &Dialer{
		net: n,
		laddr: tcpip.FullAddress{
			NIC:  n.defaultNIC,
			Addr: tcpip.AddrFromSlice(laddr),
			Port: port,
		},
	}
}

func IsLinkLocal(ip net.IP) bool {
	_, linklocalv6, _ := net.ParseCIDR("fe80::/64")
	_, linklocalv4, _ := net.ParseCIDR("169.254.0.0/16")
	return linklocalv6.Contains(ip) || linklocalv4.Contains(ip)
}

func IsLoopback(ip net.IP) bool {
	localv6 := net.ParseIP("::1")
	_, localv4, _ := net.ParseCIDR("127.0.0.1/8")
	return localv6.Equal(ip) || localv4.Contains(ip)
}

func IsPrivateNetwork(ip net.IP) bool {
	_, privatev6, _ := net.ParseCIDR("fd00::/8")
	_, priv24, _ := net.ParseCIDR("10.0.0.0/8")
	_, priv20, _ := net.ParseCIDR("172.16.0.0/12")
	_, priv16, _ := net.ParseCIDR("192.168.0.0/16")
	return privatev6.Contains(ip) || priv16.Contains(ip) || priv20.Contains(ip) || priv24.Contains(ip)
}

// IsBogon returns true if dialing the address would fail due to gonet.
// [IsPrivateNetwork] is left out because it will still remote, but it can be used to help check incoming ip addresses.
func IsBogon(ip net.IP) bool {
	for _, filter := range []func(net.IP) bool{
		IsLoopback,
		IsLinkLocal,
		net.IPv4allsys.Equal,
		net.IPv4allrouter.Equal,
		net.IPv4bcast.Equal,
	} {
		if filter(ip) {
			return true
		}
	}
	return false
}

var (
	ErrInvalidLocalIP  = errors.New("local ip is invalid")
	ErrInvalidRemoteIP = errors.New("remote ip is invalid")
)

// DialTCP initiates a TCP connection with a remote TCP listener.
func (d *Dialer) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if IsBogon(d.laddr.Addr.AsSlice()) {
		return nil, ErrInvalidLocalIP
	} else if IsBogon(addr.IP) {
		return nil, ErrInvalidRemoteIP
	}

	return gonet.DialTCPWithBind(ctx, d.net.stack, d.laddr, tcpip.FullAddress{
		NIC:  d.net.defaultNIC,
		Addr: tcpip.AddrFromSlice(addr.IP.To4()),
		Port: uint16(addr.Port),
	}, ipv4.ProtocolNumber)
}

// DialUDP dials a UDP network.
// Addresses in the 127.0.0.1/24 range
func (d *Dialer) DialUDP(addr *net.UDPAddr) (net.PacketConn, error) {
	if IsBogon(d.laddr.Addr.AsSlice()) {
		return nil, ErrInvalidLocalIP
	} else if IsBogon(addr.IP) {
		return nil, ErrInvalidRemoteIP
	}

	return gonet.DialUDP(d.net.stack, &d.laddr, &tcpip.FullAddress{
		NIC:  d.net.defaultNIC,
		Addr: tcpip.AddrFromSlice(addr.IP.To4()),
		Port: uint16(addr.Port),
	}, ipv4.ProtocolNumber)
}
