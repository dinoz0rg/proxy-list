package models

type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeSOCKS4 ProxyType = "socks4"
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeAll    ProxyType = "all"
)

var ProxyTypes = []ProxyType{ProxyTypeHTTP, ProxyTypeSOCKS4, ProxyTypeSOCKS5}

func (p ProxyType) String() string {
	return string(p)
}

func ProtocolPrefix(p ProxyType) string {
	return p.String() + "://"
}
