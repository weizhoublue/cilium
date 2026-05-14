// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netdevice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestGetIfaceFirstIPv4Address_IgnoresTentativeDadfailed verifies that
// tentative and dadfailed IPv4 addresses are skipped.
func TestGetIfaceFirstIPv4Address_IgnoresTentativeDadfailed(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		dummyName := "testdummy0"
		err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}})
		require.NoError(t, err)

		link, err := safenetlink.LinkByName(dummyName)
		require.NoError(t, err)
		defer netlink.LinkDel(link)

		// Add a tentative IPv4 address first
		_, tentativeNet, _ := net.ParseCIDR("10.0.0.1/24")
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: tentativeNet,
			Flags: unix.IFA_F_TENTATIVE,
		})
		require.NoError(t, err)

		// Then add a stable IPv4 address
		_, stableNet, _ := net.ParseCIDR("10.0.0.2/24")
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: stableNet,
		})
		require.NoError(t, err)

		addr, err := GetIfaceFirstIPv4Address(dummyName)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.2", addr.String())

		return nil
	})
}

// TestGetIfaceFirstIPv6Address_IgnoresTentativeDadfailed verifies that
// tentative and dadfailed IPv6 addresses are skipped.
func TestGetIfaceFirstIPv6Address_IgnoresTentativeDadfailed(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		dummyName := "testdummy1"
		err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}})
		require.NoError(t, err)

		link, err := safenetlink.LinkByName(dummyName)
		require.NoError(t, err)
		defer netlink.LinkDel(link)

		// Add a tentative IPv6 address first
		_, tentativeNet, _ := net.ParseCIDR("2001:db8::1/64")
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: tentativeNet,
			Flags: unix.IFA_F_TENTATIVE,
		})
		require.NoError(t, err)

		// Add a dadfailed IPv6 address next
		_, dadfailedNet, _ := net.ParseCIDR("2001:db8::2/64")
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: dadfailedNet,
			Flags: unix.IFA_F_DADFAILED,
		})
		require.NoError(t, err)

		// Then add a stable global unicast IPv6 address
		_, stableNet, _ := net.ParseCIDR("2001:db8::3/64")
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: stableNet,
		})
		require.NoError(t, err)

		addr, err := GetIfaceFirstIPv6Address(dummyName)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::3", addr.String())

		return nil
	})
}
