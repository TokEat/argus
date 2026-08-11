package common

import (
	"testing"

	"dddd/scanner/structs"
)

func TestInitializeLegacyResponseStoresUsesSharedFactory(t *testing.T) {
	originalConfig := structs.GlobalConfig
	originalBody := structs.GlobalHttpBodyHMap
	originalHeader := structs.GlobalHttpHeaderHMap
	originalBanner := structs.GlobalBannerHMap
	t.Cleanup(func() {
		if structs.GlobalHttpBodyHMap != nil && structs.GlobalHttpBodyHMap != originalBody {
			structs.GlobalHttpBodyHMap.Close()
		}
		if structs.GlobalHttpHeaderHMap != nil && structs.GlobalHttpHeaderHMap != originalHeader {
			structs.GlobalHttpHeaderHMap.Close()
		}
		if structs.GlobalBannerHMap != nil && structs.GlobalBannerHMap != originalBanner {
			structs.GlobalBannerHMap.Close()
		}
		structs.GlobalConfig = originalConfig
		structs.GlobalHttpBodyHMap = originalBody
		structs.GlobalHttpHeaderHMap = originalHeader
		structs.GlobalBannerHMap = originalBanner
	})

	structs.GlobalConfig = structs.Config{Targets: []string{"https://example.com"}, NoDirSearch: true, NoHostBind: true}
	if err := initializeLegacyResponseStores(); err != nil {
		t.Fatal(err)
	}
	if structs.GlobalHttpBodyHMap == nil || structs.GlobalHttpHeaderHMap == nil || structs.GlobalBannerHMap == nil {
		t.Fatal("legacy response stores were not initialized")
	}
	if err := structs.GlobalHttpHeaderHMap.Set("header", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if got, ok := structs.GlobalHttpHeaderHMap.Get("header"); !ok || string(got) != "value" {
		t.Fatalf("legacy response store Get = %q, %v", got, ok)
	}
}
