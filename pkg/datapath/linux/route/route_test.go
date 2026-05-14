// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func parseIP(ip string) *net.IP {
	result := net.ParseIP(ip)
	return &result
}

func TestToIPCommand(t *testing.T) {
	routes := []*Route{
		{
			Prefix: net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(8, 32),
			},
			Nexthop: parseIP("192.168.0.1"),
		},
		{
			Prefix: net.IPNet{
				IP:   net.ParseIP("::1"),
				Mask: net.CIDRMask(64, 128),
			},
			Nexthop: parseIP("ff02::2"),
		},
	}
	for _, r := range routes {
		dev := "eth0"
		v6 := "-6 "
		if r.Prefix.IP.To4() != nil {
			v6 = ""
		}
		masklen, _ := r.Prefix.Mask.Size()
		expRes := fmt.Sprintf("ip %sroute add %s/%d via %s dev %s", v6,
			r.Prefix.IP.String(), masklen, r.Nexthop.String(), dev)
		result := strings.Join(r.ToIPCommand(dev), " ")
		require.Equal(t, expRes, result)

		r.Nexthop = nil
		expRes = fmt.Sprintf("ip %sroute add %s/%d dev %s", v6,
			r.Prefix.IP.String(), masklen, dev)
		result = strings.Join(r.ToIPCommand(dev), " ")
		require.Equal(t, expRes, result)
	}
}

func TestLogAttrs(t *testing.T) {
	_, prefix, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	nexthop := net.ParseIP("192.168.0.1")
	local := net.ParseIP("10.0.0.1")

	route := Route{
		Prefix:  *prefix,
		Nexthop: &nexthop,
		Local:   local,
		Device:  "eth0",
	}

	attrs := route.LogAttrs()

	var foundPrefix, foundNexthop, foundLocal, foundIface bool
	for _, a := range attrs {
		attr, ok := a.(slog.Attr)
		require.True(t, ok)
		switch attr.Key {
		case logfields.Prefix:
			require.Equal(t, "10.0.0.0/8", attr.Value.String())
			foundPrefix = true
		case logfields.RouteNextHop:
			require.Equal(t, "192.168.0.1", attr.Value.String())
			foundNexthop = true
		case logfields.RouteLocal:
			require.Equal(t, "10.0.0.1", attr.Value.String())
			foundLocal = true
		case logfields.Interface:
			require.Equal(t, "eth0", attr.Value.String())
			foundIface = true
		}
	}

	require.True(t, foundPrefix, "prefix attr not found")
	require.True(t, foundNexthop, "nexthop attr not found")
	require.True(t, foundLocal, "local attr not found")
	require.True(t, foundIface, "interface attr not found")
}

func TestLogAttrsNilNexthop(t *testing.T) {
	_, prefix, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	local := net.ParseIP("10.0.0.1")

	route := Route{
		Prefix:  *prefix,
		Nexthop: nil,
		Local:   local,
		Device:  "eth0",
	}

	attrs := route.LogAttrs()

	var foundNexthop bool
	for _, a := range attrs {
		attr, ok := a.(slog.Attr)
		require.True(t, ok)
		if attr.Key == logfields.RouteNextHop {
			require.Equal(t, "<nil>", attr.Value.String())
			foundNexthop = true
		}
	}

	require.True(t, foundNexthop)
}
