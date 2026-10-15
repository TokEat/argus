package portscan

// SipHash-2-4 matching masscan's crypto-siphash24.c (Aumasson/Bernstein).

func siphash24(in []byte, key [2]uint64) uint64 {
	v0 := uint64(0x736f6d6570736575)
	v1 := uint64(0x646f72616e646f6d)
	v2 := uint64(0x6c7967656e657261)
	v3 := uint64(0x7465646279746573)

	k0 := key[0]
	k1 := key[1]
	v3 ^= k1
	v2 ^= k0
	v1 ^= k1
	v0 ^= k0

	n := len(in)
	end := n - (n % 8)
	for i := 0; i < end; i += 8 {
		m := uint64(in[i]) |
			uint64(in[i+1])<<8 |
			uint64(in[i+2])<<16 |
			uint64(in[i+3])<<24 |
			uint64(in[i+4])<<32 |
			uint64(in[i+5])<<40 |
			uint64(in[i+6])<<48 |
			uint64(in[i+7])<<56
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
	}

	b := uint64(n) << 56
	switch n & 7 {
	case 7:
		b |= uint64(in[end+6]) << 48
		fallthrough
	case 6:
		b |= uint64(in[end+5]) << 40
		fallthrough
	case 5:
		b |= uint64(in[end+4]) << 32
		fallthrough
	case 4:
		b |= uint64(in[end+3]) << 24
		fallthrough
	case 3:
		b |= uint64(in[end+2]) << 16
		fallthrough
	case 2:
		b |= uint64(in[end+1]) << 8
		fallthrough
	case 1:
		b |= uint64(in[end])
	}

	v3 ^= b
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= b

	v2 ^= 0xff
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = rotl64(*v1, 13)
	*v1 ^= *v0
	*v0 = rotl64(*v0, 32)

	*v2 += *v3
	*v3 = rotl64(*v3, 16)
	*v3 ^= *v2

	*v0 += *v3
	*v3 = rotl64(*v3, 21)
	*v3 ^= *v0

	*v2 += *v1
	*v1 = rotl64(*v1, 17)
	*v1 ^= *v2
	*v2 = rotl64(*v2, 32)
}

func rotl64(x uint64, b uint) uint64 {
	return (x << b) | (x >> (64 - b))
}
