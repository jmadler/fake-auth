package password

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrTooShort is returned when the password is shorter than the minimum length.
var ErrTooShort = errors.New("password is too short")

// ErrTooWeak is returned when the password is in the common weak password list.
var ErrTooWeak = errors.New("password is too weak or commonly used")

// commonWeakPasswords is a list of frequently used weak passwords to reject.
var commonWeakPasswords = map[string]struct{}{
	"password":     {},
	"password1":    {},
	"password12":   {},
	"password123": {},
	"123456":       {},
	"12345678":     {},
	"123456789":    {},
	"qwerty":       {},
	"abc123":       {},
	"monkey":       {},
	"letmein":      {},
	"trustno1":     {},
	"dragon":       {},
	"baseball":     {},
	"football":     {},
	"iloveyou":     {},
	"master":       {},
	"sunshine":     {},
	"princess":     {},
	"admin":        {},
	"admin123":     {},
	"welcome":      {},
	"welcome1":     {},
	"login":        {},
	"pass":         {},
	"passw0rd":     {},
	"Password1":    {},
	"Password12":   {},
	"Password123":  {},
	"changeme":     {},
	"secret":       {},
	"test":         {},
	"test123":      {},
}

// Validate checks a password against the policy. Returns an error if invalid.
func Validate(password string) error {
	lower := strings.ToLower(password)
	if _, weak := commonWeakPasswords[lower]; weak {
		return ErrTooWeak
	}
	minLen := minLength()
	if len(password) < minLen {
		return fmt.Errorf("%w: must be at least %d characters", ErrTooShort, minLen)
	}
	return nil
}

func minLength() int {
	if v := os.Getenv("PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 8
}
