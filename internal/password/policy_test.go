package password

import (
	"errors"
	"os"
	"testing"
)

func TestValidate_MinLength(t *testing.T) {
	os.Unsetenv("PASSWORD_MIN_LENGTH")
	// Default min 8
	if err := Validate("short"); err == nil {
		t.Error("expected error for short password")
	} else if !errors.Is(err, ErrTooShort) {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
	if err := Validate("longenough"); err != nil {
		t.Errorf("expected nil for 9-char password, got %v", err)
	}
	if err := Validate("Valid8Char"); err != nil {
		t.Errorf("expected nil for 8-char password, got %v", err)
	}
}

func TestValidate_MinLengthConfigurable(t *testing.T) {
	os.Setenv("PASSWORD_MIN_LENGTH", "12")
	defer os.Unsetenv("PASSWORD_MIN_LENGTH")
	if err := Validate("short"); err == nil {
		t.Error("expected error for short password")
	}
	if err := Validate("longpassword"); err != nil {
		t.Errorf("expected nil for 12-char password, got %v", err)
	}
}

func TestValidate_WeakPasswords(t *testing.T) {
	os.Unsetenv("PASSWORD_MIN_LENGTH")
	weak := []string{"password", "password123", "123456", "admin", "Password1", "qwerty"}
	for _, p := range weak {
		if err := Validate(p); err == nil {
			t.Errorf("expected error for weak password %q", p)
		} else if !errors.Is(err, ErrTooWeak) {
			t.Errorf("password %q: expected ErrTooWeak, got %v", p, err)
		}
	}
}

func TestValidate_AcceptStrong(t *testing.T) {
	os.Unsetenv("PASSWORD_MIN_LENGTH")
	strong := []string{"xK9#mL2@pQ", "SecurePass99!", "myC0mpl3xP4ss", "Tr0ub4dor&3"}
	for _, p := range strong {
		if err := Validate(p); err != nil {
			t.Errorf("expected nil for password %q, got %v", p, err)
		}
	}
}
