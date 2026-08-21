package gonmap

import "strings"

const adbMagic = "\xbc\xb1\xa7\xb1"

func isADBBanner(raw string) bool {
	if !strings.Contains(raw, adbMagic) {
		return false
	}
	return strings.HasPrefix(raw, "CNXN") || strings.HasPrefix(raw, "AUTH")
}

func adbBannerInfo(raw string) string {
	if strings.HasPrefix(raw, "AUTH") {
		return "auth=required"
	}
	if i := strings.Index(raw, "ro.product.model="); i >= 0 {
		rest := raw[i+len("ro.product.model="):]
		if end := strings.IndexAny(rest, ";\x00"); end >= 0 {
			rest = rest[:end]
		}
		return "model=" + rest
	}
	return ""
}
