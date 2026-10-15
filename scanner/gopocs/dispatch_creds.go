package gopocs

import (
	"strings"

	"github.com/P0lar1ght/argus/scanner/structs"
)

// DispatchCreds carries CLI/Server credential overrides into GoPoc dispatch.
type DispatchCreds struct {
	Password       string
	PasswordFile   string
	UserAppend     []string
	PasswordAppend []string
	NoBrute        bool
	// CredentialPairLimit caps user:pass attempts per target via
	// limitUserPasswd. Zero keeps the historical unlimited behavior; sealed
	// credential-validation tasks set it from the scan policy.
	CredentialPairLimit int
	Modules             string
}

func isServiceBruteTask(name string) bool {
	switch name {
	case "Shiro-Key-Crack", "ViewState-Key-Crack":
		return false
	case "VNC-Scan", "DM-Scan", "Kingbase-Scan":
		return true
	default:
		return strings.HasSuffix(name, "-Crack")
	}
}

func applyDispatchCreds(info *structs.HostInfo, creds DispatchCreds) {
	if info == nil {
		return
	}
	info.Password = creds.Password
	info.PasswordFile = creds.PasswordFile
	info.UserAppend = append([]string(nil), creds.UserAppend...)
	info.PasswordAppend = append([]string(nil), creds.PasswordAppend...)
	info.CredentialPairLimit = creds.CredentialPairLimit
}
