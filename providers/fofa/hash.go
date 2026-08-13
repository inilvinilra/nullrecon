package fofa

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Of(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
