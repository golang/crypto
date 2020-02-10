// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"net"
	"testing"
)

func TestManager_Listener(t *testing.T) {
	man := Manager{}
	ln := man.Listener()
	defer ln.Close()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if host != "::" || port != "443" {
		t.Errorf("Wrong host or port: %s%s", host, port)
	}
}

func TestManager_ListenerCustomAddress(t *testing.T) {
	tests := []struct {
		name         string
		m            *Manager
		address      string
		wantHostIPv6 string
		wantHostIPv4 string
		wantPort     string
	}{
		{
			name:         "PortOnly",
			m:            &Manager{},
			address:      ":4433",
			wantHostIPv6: "::",
			wantHostIPv4: "0.0.0.0",
			wantPort:     "4433",
		},
		{
			name:         "FullAddress",
			m:            &Manager{},
			address:      "127.0.0.1:443",
			wantHostIPv6: "dummy",
			wantHostIPv4: "127.0.0.1",
			wantPort:     "443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := tt.m.ListenerCustomAddress(tt.address)
			gotHost, gotPort, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if gotHost != tt.wantHostIPv6 && gotHost != tt.wantHostIPv4 {
				t.Errorf("Wrong host. Want %s or %s got %s", tt.wantHostIPv6, tt.wantHostIPv4, gotHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("Wrong port. Want %s got %s", tt.wantPort, gotPort)
			}
		})
	}
}
