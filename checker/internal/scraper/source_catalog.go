package scraper

import (
	"regexp"

	"proxies-checker/internal/models"
)

var freeProxyListPages = []string{
	"https://free-proxy-list.net/",
	"https://www.sslproxies.org/",
	"https://us-proxy.org/",
}

const anonymousProxyURL = "https://free-proxy-list.net/anonymous-proxy.html"

const ukProxyURL = "https://free-proxy-list.net/uk-proxy.html"

var githubSources = map[models.ProxyType][]string{
	models.ProxyTypeHTTP: {
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		"https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
		"https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
		"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
		"https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
		"https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
		"https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
		"https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
		"https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
	},
	models.ProxyTypeSOCKS4: {
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
		"https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
		"https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
		"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
		"https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
		"https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
		"https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
		"https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
		"https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
	},
	models.ProxyTypeSOCKS5: {
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
		"https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
		"https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
		"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
		"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
		"https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
		"https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
		"https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
		"https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		"https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
	},
	models.ProxyTypeAll: {
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
	},
}

var myProxyPattern = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})(?:#)`)

var myProxySources = map[models.ProxyType]string{
	models.ProxyTypeHTTP:   "https://www.my-proxy.com/free-proxy-list.html",
	models.ProxyTypeSOCKS4: "https://www.my-proxy.com/free-socks-4-proxy.html",
	models.ProxyTypeSOCKS5: "https://www.my-proxy.com/free-socks-5-proxy.html",
}

var openProxyListSources = map[models.ProxyType]string{
	models.ProxyTypeHTTP:   "https://api.openproxylist.xyz/http.txt",
	models.ProxyTypeSOCKS4: "https://api.openproxylist.xyz/socks4.txt",
	models.ProxyTypeSOCKS5: "https://api.openproxylist.xyz/socks5.txt",
}

const proxy5050URL = "https://proxy50-50.blogspot.com/"

const proxyScrapeURL = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text"

var proxySpaceSources = map[models.ProxyType]string{
	models.ProxyTypeHTTP:   "https://proxyspace.pro/http.txt",
	models.ProxyTypeSOCKS4: "https://proxyspace.pro/socks4.txt",
	models.ProxyTypeSOCKS5: "https://proxyspace.pro/socks5.txt",
}

var freeProxyWorldSources = []string{
	"https://www.freeproxy.world/?type=http",
	"https://www.freeproxy.world/?type=https",
	"https://www.freeproxy.world/?type=socks4",
	"https://www.freeproxy.world/?type=socks5",
}

var freeProxyUpdateSources = []string{
	"https://freeproxyupdate.com/http-proxy",
	"https://freeproxyupdate.com/https-ssl-proxy",
	"https://freeproxyupdate.com/socks4-proxy",
	"https://freeproxyupdate.com/socks5-proxy",
}

var freeProxyUpdateFilteredSources = []string{
	"https://freeproxyupdate.com/high-uptime-proxy",
	"https://freeproxyupdate.com/high-speed-proxy",
	"https://freeproxyupdate.com/low-latency-proxy",
}

type databayRequest struct {
	protocol  string
	proxyType models.ProxyType
}

type ipRoyalRequest struct {
	protocol  string
	proxyType models.ProxyType
}

var databayRequests = []databayRequest{
	{protocol: "http", proxyType: models.ProxyTypeHTTP},
	{protocol: "https", proxyType: models.ProxyTypeHTTP},
	{protocol: "socks5", proxyType: models.ProxyTypeSOCKS5},
}

const (
	databayBaseURL  = "https://databay.com/api/v1/proxy-list"
	databayPageSize = 1000
	databayMaxPages = 20
)

const socksProxyNetURL = "https://www.socks-proxy.net/"

const hideMnURL = "https://hide.mn/en/proxy-list/"

const ipRoyalFreeProxyListURL = "https://iproyal.com/free-proxy-list/"

var ipRoyalRequests = []ipRoyalRequest{
	{protocol: "http", proxyType: models.ProxyTypeHTTP},
	{protocol: "https", proxyType: models.ProxyTypeHTTP},
	{protocol: "socks4", proxyType: models.ProxyTypeSOCKS4},
	{protocol: "socks5", proxyType: models.ProxyTypeSOCKS5},
}

const ipRoyalPageSize = 100

const flamingoProxiesURL = "https://flamingoproxies.com/free-proxies"

var proxyDBSources = []string{
	"https://proxydb.net/?protocol=http",
	"https://proxydb.net/?protocol=https",
	"https://proxydb.net/?protocol=socks4",
	"https://proxydb.net/?protocol=socks5",
}

const proxyNovaURL = "https://www.proxynova.com/proxy-server-list/"

var spysOneSources = []string{
	"https://spys.one/en/free-proxy-list/",
	"https://spys.one/en/socks-proxy-list/",
}

var advancedNameSources = map[models.ProxyType]string{
	models.ProxyTypeHTTP:   "https://advanced.name/freeproxy?type=http",
	models.ProxyTypeSOCKS4: "https://advanced.name/freeproxy?type=socks4",
	models.ProxyTypeSOCKS5: "https://advanced.name/freeproxy?type=socks5",
}

const spysMeHTTPURL = "https://spys.me/proxy.txt"

const spysMeSOCKSURL = "https://spys.me/socks.txt"

const (
	proxyListOrgBaseURL  = "https://proxy-list.org/english/index.php"
	proxyListOrgMaxPages = 10
)

type proxyListPlusPage struct {
	url         string
	defaultType models.ProxyType
}

var proxyListPlusPages = []proxyListPlusPage{
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-2", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-3", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-4", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-5", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-6", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/SSL-List-1", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/SSL-List-2", defaultType: models.ProxyTypeHTTP},
	{url: "https://list.proxylistplus.com/Socks-List-1", defaultType: models.ProxyTypeSOCKS5},
	{url: "https://list.proxylistplus.com/Socks-List-2", defaultType: models.ProxyTypeSOCKS5},
}
