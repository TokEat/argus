package main

import "strings"

func canonicalArsenalType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "finger", "fingerprint":
		return "finger"
	case "workflow":
		return "workflow"
	case "dir", "dirprobe":
		return "dir"
	case "poc":
		return "poc"
	case "poc_asset", "pocasset":
		return "poc_asset"
	case "config_asset", "configasset", "dict_asset", "dictasset":
		return "config_asset"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}
