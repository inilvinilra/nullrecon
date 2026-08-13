package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func Canonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

func Hash(v any) ([32]byte, error) {
	data, err := Canonical(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func HashHex(v any) (string, error) {
	sum, err := Hash(v)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
