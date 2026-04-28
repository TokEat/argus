package main

import "testing"

func TestBuildCloudAdvertiseAddrsUsesDetectedHostForWildcardBind(t *testing.T) {
	grpcAddr, apiURL, err := buildCloudAdvertiseAddrs(50051, ":8085", "", "", func() (string, error) {
		return "10.0.0.12", nil
	})
	if err != nil {
		t.Fatalf("buildCloudAdvertiseAddrs: %v", err)
	}
	if grpcAddr != "10.0.0.12:50051" {
		t.Fatalf("unexpected gRPC advertise addr: %s", grpcAddr)
	}
	if apiURL != "http://10.0.0.12:8085" {
		t.Fatalf("unexpected API advertise URL: %s", apiURL)
	}
}

func TestBuildCloudAdvertiseAddrsHonorsExplicitPublicOverrides(t *testing.T) {
	grpcAddr, apiURL, err := buildCloudAdvertiseAddrs(50051, ":8085", "198.51.100.8", "https://scan.example.com", func() (string, error) {
		t.Fatal("detectHost should not be called when public overrides are set")
		return "", nil
	})
	if err != nil {
		t.Fatalf("buildCloudAdvertiseAddrs: %v", err)
	}
	if grpcAddr != "198.51.100.8:50051" {
		t.Fatalf("unexpected gRPC advertise addr: %s", grpcAddr)
	}
	if apiURL != "https://scan.example.com" {
		t.Fatalf("unexpected API advertise URL: %s", apiURL)
	}
}
