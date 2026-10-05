package protocolwire

import "testing"

func TestRSSPIRSDLengthConsistent(t *testing.T) {
	le := []byte{
		0x01, 0x80,
		0x01, 0x00, 0x02, 0x00,
		0x07, 0x00, 0x00, 0x00,
		0x0A, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0xAA, 0xBB,
		0x12, 0x34,
	}
	info, ok := RSSPI(le)
	if !ok {
		t.Fatal("little-endian RSD was not recognized")
	}
	if info.Type != "rsd-a" || info.Category != 0x01 || info.Source != 1 || info.Dest != 2 || info.Sequence != 7 {
		t.Fatalf("info = %+v", info)
	}
	if info.Extra() != "frame=rsd-a cat=1 src=1 dst=2 seq=7" {
		t.Fatalf("extra = %q", info.Extra())
	}

	be := []byte{
		0x02, 0x82,
		0x00, 0x01, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x09,
		0x00, 0x08,
		0, 0, 0, 0, 0, 0, 0, 0,
		0xAB, 0xCD,
	}
	info, ok = RSSPI(be)
	if !ok || info.Type != "rsd" || info.Category != 0x02 || info.Source != 1 || info.Dest != 2 || info.Sequence != 9 {
		t.Fatalf("big-endian info = %+v ok=%v", info, ok)
	}

	sse := []byte{
		0x01, 0x90,
		0x00, 0x10, 0x00, 0x20,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		0x00, 0x00,
	}
	info, ok = RSSPI(sse)
	if !ok || info.Type != "sse" || info.Category != 0x01 || info.Extra() != "frame=sse cat=1" {
		t.Fatalf("sse info = %+v ok=%v extra=%q", info, ok, info.Extra())
	}

	ssr := make([]byte, 25)
	ssr[0], ssr[1] = 0x01, 0x91
	ssr[2], ssr[3], ssr[4], ssr[5] = 0x00, 0x10, 0x00, 0x20
	ssr[22] = 0x01
	info, ok = RSSPI(ssr)
	if !ok || info.Type != "ssr" || info.Extra() != "frame=ssr cat=1" {
		t.Fatalf("ssr info = %+v ok=%v extra=%q", info, ok, info.Extra())
	}
}

func TestRSSPIRejectsInconsistentFrames(t *testing.T) {
	good := []byte{
		0x01, 0x81,
		0x01, 0x00, 0x02, 0x00,
		0, 0, 0, 0,
		0x08, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0,
		0x12, 0x34,
	}
	shortLen := append([]byte{}, good...)
	shortLen[10] = 0x07
	sourceZero := append([]byte{}, good...)
	sourceZero[2], sourceZero[3] = 0, 0
	broadcast := append([]byte{}, good...)
	broadcast[4], broadcast[5] = 0xFF, 0xFF
	trailing := append(append([]byte{}, good...), 0x00)
	ambiguous := make([]byte, 14+257)
	ambiguous[0], ambiguous[1] = 0x01, 0x80
	ambiguous[2], ambiguous[3] = 0x01, 0x00
	ambiguous[4], ambiguous[5] = 0x02, 0x00
	ambiguous[10], ambiguous[11] = 0x01, 0x01

	rejects := [][]byte{
		shortLen,
		sourceZero,
		broadcast,
		trailing,
		ambiguous,
		{0x01, 0x83, 0x01, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x03, 0x80, 0x01, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x00, 0x1E, 0x01, 0x1A, 0x00, 0x00, 0x01, 0x01, 0x10, 0x89},
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x2b, 0x0e, 0x01},
		{0x68, 0x04, 0x07, 0x00, 0x00, 0x00},
		{0x01, 0x90, 0x00, 0x00, 0x00, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0},
		{0x01, 0x90, 0x00, 0x10, 0xFF, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0},
		make([]byte, 21),
		make([]byte, 25),
	}
	for _, raw := range rejects {
		if _, ok := RSSPI(raw); ok {
			t.Fatalf("accepted %x", raw)
		}
	}
}
