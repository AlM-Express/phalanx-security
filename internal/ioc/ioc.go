package ioc

import (
	"net/url"
	"strings"

	"github.com/spf13/viper"
)

// extractHost parses a URL or raw domain string and returns the lowercase hostname.
func extractHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	// Treat it as a bare hostname
	return strings.ToLower(strings.Split(raw, "/")[0])
}

// domainMatches returns true if host equals blocked or is a subdomain of it.
func domainMatches(host, blocked string) bool {
	blocked = strings.ToLower(blocked)
	host = strings.ToLower(host)
	return host == blocked || strings.HasSuffix(host, "."+blocked)
}

// CheckDomain returns true if the URL points to a known bad actor.
func CheckDomain(rawURL string) bool {
	host := extractHost(rawURL)

	hardcodedMalicious := []string{
		"example-c2.com",
		"malicious-drop.net",
		"evil.xyz",
	}

	for _, domain := range hardcodedMalicious {
		if domainMatches(host, domain) {
			return true
		}
	}

	blockedDomains := viper.GetStringSlice("network.block")
	for _, domain := range blockedDomains {
		if domainMatches(host, domain) {
			return true
		}
	}

	return false
}

// CheckHash returns true if a given SHA256 matches a blocked hash from config.
func CheckHash(hash string) bool {
	blockedHashes := viper.GetStringSlice("integrity.block")
	for _, h := range blockedHashes {
		if strings.EqualFold(hash, h) {
			return true
		}
	}
	return false
}
