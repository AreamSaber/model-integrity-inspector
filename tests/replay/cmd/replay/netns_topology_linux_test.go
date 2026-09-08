//go:build linux && replay_netns

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// These seam checks run inside the mandatory parent test, not as additional
// success events in the wrapper. They do not mint an OS-isolation receipt.
func assertNetnsEmptyTopologyPolicy(t *testing.T) {
	t.Helper()
	for _, path := range []string{"", "/proc/net/../self/status", "/proc/self/net/if_inet6", "https://invalid.example/", "/tmp/arbitrary"} {
		if raw, err := netnsReadTopologyFile(path); !errors.Is(err, unix.EINVAL) || len(raw) != 0 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_PROBE_POLICY")
		}
	}
	for _, tc := range []struct {
		addresses []net.Addr
		table     []byte
		want      bool
	}{
		{nil, nil, true},
		{nil, []byte(" \t\r\n"), true},
		{[]net.Addr{&net.IPNet{IP: net.IPv6loopback}}, nil, false},
		{[]net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1)}}, nil, false},
		{nil, []byte("00000000000000000000000000000001 01 80 10 80 lo\n"), false},
		{nil, []byte("malformed"), false},
		{nil, bytes.Repeat([]byte(" "), (64<<10)+1), false},
	} {
		if netnsNoSourceAddresses(tc.addresses, tc.table) != tc.want {
			t.Fatal("MI_REPLAY_NETNS_FAILED_PROBE_POLICY")
		}
	}
	proof := netnsTopologyProof{"net:[2]", "net:[1]", true}
	for _, tc := range []struct {
		family         int
		stage          string
		err            error
		loopback, want bool
	}{
		{unix.AF_INET6, "CONNECT", unix.EADDRNOTAVAIL, false, true},
		{unix.AF_INET, "CONNECT", unix.EADDRNOTAVAIL, false, false},
		{unix.AF_INET6, "SOCKET", unix.EADDRNOTAVAIL, false, false},
		{unix.AF_INET6, "SO_ERROR", unix.EADDRNOTAVAIL, false, false},
		{unix.AF_INET6, "CONNECT", unix.EADDRNOTAVAIL, true, false},
		{unix.AF_INET6, "CONNECT", unix.EACCES, false, false},
		{unix.AF_INET6, "CONNECT", unix.EPERM, false, false},
		{unix.AF_INET6, "CONNECT", unix.EINPROGRESS, false, false},
		{unix.AF_INET6, "CONNECT", unix.ETIMEDOUT, false, false},
		{unix.AF_INET6, "CONNECT", nil, false, false},
		{unix.AF_INET6, "CONTEXT", context.Canceled, false, false},
		{unix.AF_INET6, "CONNECT", unix.ENETUNREACH, false, true},
		{unix.AF_INET, "SO_ERROR", unix.EHOSTUNREACH, false, true},
	} {
		if netnsBlockedInEmptyNamespace(tc.family, tc.stage, tc.err, tc.loopback, proof, proof) != tc.want {
			t.Fatal("MI_REPLAY_NETNS_FAILED_PROBE_POLICY")
		}
	}
	for _, invalid := range []netnsTopologyProof{
		{}, {"", "net:[1]", true}, {"net:[2]", "", true},
		{"net:[1]", "net:[1]", true}, {"net:[2]", "net:[1]", false},
		{"net:[3]", "net:[1]", true}, {"net:[2]", "net:[4]", true},
	} {
		for _, err := range []error{unix.EADDRNOTAVAIL, unix.ENETUNREACH} {
			if netnsBlockedInEmptyNamespace(unix.AF_INET6, "CONNECT", err, false, invalid, proof) ||
				netnsBlockedInEmptyNamespace(unix.AF_INET6, "CONNECT", err, false, proof, invalid) {
				t.Fatal("MI_REPLAY_NETNS_FAILED_PROBE_POLICY")
			}
		}
	}
}
