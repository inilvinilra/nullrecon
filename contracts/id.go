package contracts

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"time"
)

const idAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,24}-[0123456789abcdefghjkmnpqrstvwxyz]{26}$`)

func NewID(prefix string) string {
	var raw [16]byte
	ms := uint64(time.Now().UTC().UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	if _, err := rand.Read(raw[6:]); err != nil {
		panic(fmt.Sprintf("contracts: entropy failure: %v", err))
	}
	return prefix + "-" + encode(raw)
}

func ValidID(value string) bool {
	return idPattern.MatchString(value)
}

func encode(raw [16]byte) string {
	var out [26]byte
	v := make([]byte, 16)
	copy(v, raw[:])
	for i := 25; i >= 0; i-- {
		var rem byte
		for j := 0; j < 16; j++ {
			cur := uint16(rem)<<8 | uint16(v[j])
			v[j] = byte(cur / 32)
			rem = byte(cur % 32)
		}
		out[i] = idAlphabet[rem]
	}
	return string(out[:])
}
