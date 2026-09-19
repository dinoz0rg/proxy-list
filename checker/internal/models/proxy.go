package models

import (
	"net/netip"
	"strings"
	"time"
)

// NormalizeProxyAddr trims and validates a proxy address.
func NormalizeProxyAddr(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	addrPort, err := netip.ParseAddrPort(raw)
	if err != nil || !addrPort.Addr().Is4() || addrPort.Port() == 0 {
		return "", false
	}

	return addrPort.String(), true
}

// ProxyResult holds scraped proxies grouped by protocol.
type ProxyResult struct {
	HTTP   []string
	SOCKS4 []string
	SOCKS5 []string
}

// Total returns the total number of proxies across all protocols.
func (r *ProxyResult) Total() int {
	return len(r.HTTP) + len(r.SOCKS4) + len(r.SOCKS5)
}

// Merge appends all proxies from another ProxyResult.
func (r *ProxyResult) Merge(other *ProxyResult) {
	r.AppendByType(ProxyTypeHTTP, other.HTTP...)
	r.AppendByType(ProxyTypeSOCKS4, other.SOCKS4...)
	r.AppendByType(ProxyTypeSOCKS5, other.SOCKS5...)
}

// AppendByType appends addresses to the appropriate protocol slice.
func (r *ProxyResult) AppendByType(proxyType ProxyType, addrs ...string) {
	validAddrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if normalized, ok := NormalizeProxyAddr(addr); ok {
			validAddrs = append(validAddrs, normalized)
		}
	}

	switch proxyType {
	case ProxyTypeHTTP:
		r.HTTP = append(r.HTTP, validAddrs...)
	case ProxyTypeSOCKS4:
		r.SOCKS4 = append(r.SOCKS4, validAddrs...)
	case ProxyTypeSOCKS5:
		r.SOCKS5 = append(r.SOCKS5, validAddrs...)
	}
}

// CheckedProxy represents a validated working proxy with metadata.
type CheckedProxy struct {
	Address   string    `json:"address"`
	ProxyType string    `json:"proxy_type"`
	LatencyMs float64   `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
}

// NewCheckedProxy creates a CheckedProxy with the current UTC timestamp.
func NewCheckedProxy(address, proxyType string, latencyMs float64) CheckedProxy {
	return CheckedProxy{
		Address:   address,
		ProxyType: proxyType,
		LatencyMs: latencyMs,
		CheckedAt: time.Now().UTC(),
	}
}

// CheckedResult holds checked proxies grouped by protocol.
type CheckedResult struct {
	HTTP   []CheckedProxy
	SOCKS4 []CheckedProxy
	SOCKS5 []CheckedProxy
}

// Total returns the total number of working proxies.
func (r *CheckedResult) Total() int {
	return len(r.HTTP) + len(r.SOCKS4) + len(r.SOCKS5)
}
