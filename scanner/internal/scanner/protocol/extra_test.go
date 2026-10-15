package protocol

import (
	"strings"
	"testing"

	"github.com/lcvvvv/gonmap"
)

func TestFingerprintExtraKeepsHostWorkgroupAndOS(t *testing.T) {
	got := fingerprintExtra(&gonmap.FingerPrint{
		Hostname:        "DC01",
		Info:            "workgroup: CORP",
		OperatingSystem: "Windows 10",
		DeviceType:      "general purpose",
	})
	for _, want := range []string{"host=DC01", "workgroup=CORP", "os=Windows_10", "device=general_purpose"} {
		if !strings.Contains(got, want) {
			t.Fatalf("extra %q missing %q", got, want)
		}
	}
}

func TestSMBExtraFromUTF16Names(t *testing.T) {
	raw := []byte{
		0x00, 0x00, 0x00, 0x40, 0xff, 'S', 'M', 'B',
		'C', 0x00, 'O', 0x00, 'R', 0x00, 'P', 0x00, 0x00, 0x00,
		'D', 0x00, 'C', 0x00, '0', 0x00, '1', 0x00, 0x00, 0x00,
		'W', 0x00, 'i', 0x00, 'n', 0x00, 'd', 0x00, 'o', 0x00, 'w', 0x00, 's', 0x00, 0x00, 0x00,
	}
	got := smbExtra(raw)
	if !strings.Contains(got, "workgroup=CORP") || !strings.Contains(got, "host=DC01") || !strings.Contains(got, "os=Windows") {
		t.Fatalf("smb extra = %q", got)
	}
}

func TestServiceDetailKeepsUsefulExtrasAndCapsLength(t *testing.T) {
	got := ServiceDetail("OpenSSH", "8.9", "banner=SSH-2.0-OpenSSH_8.9p1_Ubuntu-3ubuntu0.1 host=mail.example")
	if !strings.Contains(got, "host=mail.example") {
		t.Fatalf("detail lost host: %q", got)
	}
	if strings.Contains(got, "banner=SSH-2.0-OpenSSH") && strings.Contains(strings.ToLower(got), "openssh") && strings.Count(strings.ToLower(got), "openssh") > 2 {
		t.Fatalf("detail repeats product too much: %q", got)
	}
	huge := "a=" + strings.Repeat("x", 80) + " b=" + strings.Repeat("y", 80) + " c=" + strings.Repeat("z", 80) + " d=" + strings.Repeat("w", 80) + " e=" + strings.Repeat("v", 80) + " f=" + strings.Repeat("u", 80)
	limited := ServiceDetail("svc", "1", huge)
	if len(limited) > detailMax {
		t.Fatalf("detail too long: %d %q", len(limited), limited)
	}
}

func TestBannerExtraSMTPAndMySQL(t *testing.T) {
	smtp := bannerExtra("220 mail.example ESMTP Postfix\r\n", "smtp")
	if !strings.Contains(smtp, "banner=220_mail.example_ESMTP_Postfix") {
		t.Fatalf("smtp extra = %q", smtp)
	}
	mysql := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', '6', 0x00, 0x01}
	got := bannerExtra(string(mysql), "mysql")
	if !strings.Contains(got, "server=8.0.36") {
		t.Fatalf("mysql extra = %q", got)
	}
}

func TestBinaryProtocolBannerExtraUsesPrintableSummary(t *testing.T) {
	got := bannerExtra("\x00\x00\x11\x11name rabbit at port 25672\n", "epmd")
	if !strings.HasPrefix(got, "info=") || strings.ContainsAny(got, "\x00\r\n") {
		t.Fatalf("binary protocol extra should be printable info, got %q", got)
	}
}

func TestMergeRecordKeepsFingerprintHost(t *testing.T) {
	base := recordFromFingerprint(&gonmap.FingerPrint{
		Service:     "microsoft-ds",
		ProductName: "Microsoft Windows SMB",
		Hostname:    "DC01",
		Info:        "workgroup: CORP",
	})
	next := recordFromFingerprint(&gonmap.FingerPrint{Service: "netbios", ProductName: "NetBIOS"})
	got := mergeRecord(base, next)
	if !strings.Contains(got.Extra, "host=DC01") || !strings.Contains(got.Extra, "workgroup=CORP") {
		t.Fatalf("merged extra lost host: %+v", got)
	}
}
