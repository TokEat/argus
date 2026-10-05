package protocolwire

import "testing"

func TestRSSPIIALEPublishedHeader(t *testing.T) {
	// Header bytes and checksum from BJMT RsspII CrcToolTest / AleFrame.
	header := []byte{0x00, 0x1E, 0x01, 0x1A, 0x00, 0x00, 0x01, 0x01, 0x10, 0x89}
	if got := crc16CCITTFalse(header[:8]); got != 0x1089 {
		t.Fatalf("crc = %#x, want 0x1089", got)
	}
	body := make([]byte, 22)
	raw := append(append([]byte{}, header...), body...)
	info, ok := RSSPIIALE(raw)
	if !ok {
		t.Fatal("published ALE header was not recognized")
	}
	if info.Type != "cr" || info.Application != 0x1A || info.Sequence != 0 || !info.Normal {
		t.Fatalf("info = %+v", info)
	}
	if info.Extra() != "ale=cr app=26 link=normal seq=0" {
		t.Fatalf("extra = %q", info.Extra())
	}

	raw[9] ^= 0x01
	if _, ok := RSSPIIALE(raw); ok {
		t.Fatal("corrupted checksum was accepted")
	}
}

func TestRSSPIIALEKeepaliveAndRejects(t *testing.T) {
	alive := []byte{0x00, 0x08, 0x01, 0x16, 0x00, 0x2C, 0x00, 0xFF, 0x00, 0x00}
	info, ok := RSSPIIALE(alive)
	if !ok || info.Type != "kaa" || info.Normal || info.Application != 0x16 || info.Sequence != 0x2C {
		t.Fatalf("keepalive info=%+v ok=%v", info, ok)
	}
	alive[1] = 0x09
	if _, ok := RSSPIIALE(alive); ok {
		t.Fatal("keepalive with a body was accepted")
	}

	rejects := [][]byte{
		{0x00, 0x1E, 0x02, 0x1A, 0x00, 0x00, 0x01, 0x01, 0x10, 0x89},
		{0x00, 0x1E, 0x01, 0x1A, 0x00, 0x00, 0x02, 0x01, 0x10, 0x89},
		{0x00, 0x1E, 0x01, 0x1A, 0x00, 0x00, 0x01, 0x05, 0x10, 0x89},
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x2b, 0x0e, 0x01},
		{0x01, 0x02, 0x03},
	}
	for _, raw := range rejects {
		if _, ok := RSSPIIALE(raw); ok {
			t.Fatalf("accepted %x", raw)
		}
	}
}
