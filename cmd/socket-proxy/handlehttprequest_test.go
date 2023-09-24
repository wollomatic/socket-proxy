package main

import (
	"github.com/wollomatic/socket-proxy/internal/config"
	"net"
	"testing"
)

func TestIsAllowedIP(t *testing.T) {
	tests := []struct {
		input       string
		allowedCIDR string
		expected    bool
		expectError bool
	}{
		{"192.168.1.1:1234", "0.0.0.0/0", true, false},
		{"127.0.0.1:5432", "127.0.0.1/32", true, false},
		{"172.13.2.4:54320", "127.0.0.1/32", false, false},
		{"172.13.2.4", "127.0.0.1/32", false, true},
	}
	for _, test := range tests {
		_, config.AllowedNetwork, _ = net.ParseCIDR(test.allowedCIDR)
		result, err := isAllowedIP(test.input)
		if result != test.expected || (err != nil) != test.expectError {
			t.Errorf("For input %q, expected %v, %v, but got %v, %v", test.input, test.expected, test.expectError, result, err != nil)
		}
	}
}
