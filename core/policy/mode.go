package policy

import "fmt"

type Mode string

const (
	ModePassive        Mode = "passive"
	ModeSafeActive     Mode = "safeactive"
	ModeAuthorizedTest Mode = "authorizedtest"
	ModeWatchOnly      Mode = "watchonly"
)

func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModePassive, ModeSafeActive, ModeAuthorizedTest, ModeWatchOnly:
		return Mode(value), nil
	}
	return "", fmt.Errorf("policy: unknown mode %q", value)
}

func (m Mode) Valid() bool {
	_, err := ParseMode(string(m))
	return err == nil
}

func (m Mode) rank() int {
	switch m {
	case ModeWatchOnly:
		return 0
	case ModePassive:
		return 1
	case ModeSafeActive:
		return 2
	case ModeAuthorizedTest:
		return 3
	}
	return -1
}

func (m Mode) Allows(required Mode) bool {
	return m.rank() >= 0 && m.rank() >= required.rank()
}
