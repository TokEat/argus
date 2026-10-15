package utils

import "testing"

func TestIsLocalIP(t *testing.T) {
	if !IsLocalIP("192.168.1.5") || !IsLocalIP("10.0.0.1") || !IsLocalIP("127.0.0.1") {
		t.Fatal("RFC1918 and loopback must be local")
	}
	if IsLocalIP("8.8.8.8") || IsLocalIP("not-an-ip") {
		t.Fatal("public and invalid addresses must not be local")
	}
}
