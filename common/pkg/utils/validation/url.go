package validation

import (
	"fmt"
	"net/url"
	"strings"
)

// IsURL checks if a string is a valid URL
func IsURL(str string) bool {
	u, err := url.ParseRequestURI(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// ExtractHostName extracts the host part from a given URI
func ExtractHostName(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	hostName := u.Hostname()

	return hostName, nil
}

// NormalizeURL prefixes the protocol if it's missing in the URL
func NormalizeURL(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return url
}
