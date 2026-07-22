package password

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	hibpAPIBase = "https://api.pwnedpasswords.com"
	reqTimeout  = 10 * time.Second
)

// ErrBreached is returned when the password appears in a known breach.
var ErrBreached = fmt.Errorf("this password has been found in a data breach and cannot be used")

// IsBreachedCheckEnabled returns true when BREACHED_PASSWORD_CHECK=true.
func IsBreachedCheckEnabled() bool {
	return strings.ToLower(os.Getenv("BREACHED_PASSWORD_CHECK")) == "true"
}

// IsBreached checks the password against the Have I Been Pwned k-anonymity API.
// SHA1(password) is computed, first 5 chars sent to API, full hash checked in response.
// Returns nil if not breached, ErrBreached if breached, or error on API failure.
func IsBreached(password string) error {
	h := sha1.Sum([]byte(password))
	fullHex := fmt.Sprintf("%X", h)  // 40 chars
	prefix := fullHex[:5]            // HIBP uses first 5 hex chars
	suffix := fullHex[5:]

	client := &http.Client{Timeout: reqTimeout}
	if v := os.Getenv("BREACHED_PASSWORD_CHECK_TIMEOUT"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 {
			client.Timeout = time.Duration(s) * time.Second
		}
	}
	req, err := http.NewRequest(http.MethodGet, hibpAPIBase+"/range/"+prefix, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Add-Padding", "true") // optional privacy enhancement

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hibp api returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) >= 1 && parts[0] == suffix {
			return ErrBreached
		}
	}
	return nil
}
