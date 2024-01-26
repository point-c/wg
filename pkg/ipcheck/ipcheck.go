package ipcheck

import (
	"errors"
	"net"
)

// IsLinkLocal determines if the provided IP address is a link-local address.
// Link-local addresses are used in a single network segment and not routable on the larger internet.
// This function checks if the IP belongs to the IPv4 link-local range (169.254.0.0/16) or
// the IPv6 link-local range (fe80::/64).
func IsLinkLocal(ip net.IP) bool {
	_, linklocalv6, _ := net.ParseCIDR("fe80::/64")
	_, linklocalv4, _ := net.ParseCIDR("169.254.0.0/16")
	return linklocalv6.Contains(ip) || linklocalv4.Contains(ip)
}

// IsLoopback determines if the IP is either the standard IPv6 loopback (::1) or within the IPv4 loopback range.
func IsLoopback(ip net.IP) bool {
	localv6 := net.ParseIP("::1")
	_, localv4, _ := net.ParseCIDR("127.0.0.1/8")
	return localv6.Equal(ip) || localv4.Contains(ip)
}

// IsPrivateNetwork returns true if the address belongs to a private network.
// This function checks against standard private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and the IPv6 unique local address range (fd00::/8).
func IsPrivateNetwork(ip net.IP) bool {
	_, privatev6, _ := net.ParseCIDR("fd00::/8")
	_, priv24, _ := net.ParseCIDR("10.0.0.0/8")
	_, priv20, _ := net.ParseCIDR("172.16.0.0/12")
	_, priv16, _ := net.ParseCIDR("192.168.0.0/16")
	return privatev6.Contains(ip) || priv16.Contains(ip) || priv20.Contains(ip) || priv24.Contains(ip)
}

// IsBogon returns true if dialing the address would fail due to gonet restrictions.
// A bogon address is a packet routed on the public internet that claims to originate from an area of the IP address space reserved or not yet allocated.
// This function checks against known bogon conditions including loopback, link-local, and other special addresses.
// Additional conditions can be specified through the extra parameter.
func IsBogon(ip net.IP, extra ...func(net.IP) bool) bool {
	for _, filter := range append(extra, []func(net.IP) bool{
		IsLoopback,
		IsLinkLocal,
		net.IPv4allsys.Equal,
		net.IPv4allrouter.Equal,
		net.IPv4bcast.Equal,
	}...) {
		if filter(ip) {
			return true
		}
	}
	return false
}

// Error variables for invalid IP addresses
var (
	ErrInvalidLocalIP  = errors.New("local ip is invalid")
	ErrInvalidRemoteIP = errors.New("remote ip is invalid")
)
