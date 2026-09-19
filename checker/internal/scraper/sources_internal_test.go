package scraper

import (
	"encoding/base64"
	"slices"
	"testing"

	"proxies-checker/internal/models"
)

func TestParseIPPortMatchesKeepsValidHTTPAddresses(t *testing.T) {
	t.Parallel()

	html := `<div>
		<span>1.2.3.4:80</span>
		<span>ignored 999.1.1.1:70000</span>
		<p>(5.6.7.8:8080)</p>
	</div>`

	result := parseIPPortMatches(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80", "5.6.7.8:8080"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if len(result.SOCKS4) != 0 {
		t.Fatalf("expected no SOCKS4 proxies, got %v", result.SOCKS4)
	}
	if len(result.SOCKS5) != 0 {
		t.Fatalf("expected no SOCKS5 proxies, got %v", result.SOCKS5)
	}
}

func TestParseAdvancedNameTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr>
			<td>1</td>
			<td data-ip="MS4yLjMuNA=="></td>
			<td data-port="ODA="></td>
			<td><a>HTTP</a><a>ELITE</a></td>
		</tr>
		<tr>
			<td>2</td>
			<td data-ip="NS42LjcuOA=="></td>
			<td data-port="MTA4MA=="></td>
			<td><a>SOCKS4</a><a>SOCKS5</a></td>
		</tr>
		<tr>
			<td>3</td>
			<td data-ip="bad-base64"></td>
			<td data-port="MTA4MA=="></td>
			<td><a>SOCKS5</a></td>
		</tr>
	</tbody></table>`

	result := parseAdvancedNameTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseHideMnTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr><td>1.2.3.4</td><td>80</td><td><span>US</span></td><td><div>120 ms</div></td><td>HTTP, HTTPS</td><td>High</td><td>1 min.</td></tr>
		<tr><td>5.6.7.8</td><td>1080</td><td><span>DE</span></td><td><div>240 ms</div></td><td>SOCKS4, SOCKS5</td><td>High</td><td>2 min.</td></tr>
		<tr><td>999.1.1.1</td><td>70000</td><td><span>DE</span></td><td><div>240 ms</div></td><td>SOCKS5</td><td>High</td><td>2 min.</td></tr>
	</tbody></table>`

	result := parseHideMnTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseFlamingoProxiesTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr><td><strong class="font-mono">1.2.3.4</strong></td><td class="p-2">80</td><td>HTTP</td><td><button data-copy="http://1.2.3.4:80">Copy</button></td></tr>
		<tr><td><strong class="font-mono">2.3.4.5</strong></td><td class="p-2">443</td><td>HTTPS</td><td><button data-copy="https://2.3.4.5:443">Copy</button></td></tr>
		<tr><td><strong class="font-mono">5.6.7.8</strong></td><td class="p-2">1080</td><td>SOCKS4</td><td><button data-copy="socks4://5.6.7.8:1080">Copy</button></td></tr>
		<tr><td><strong class="font-mono">9.8.7.6</strong></td><td class="p-2">1081</td><td>SOCKS5</td><td><button data-copy="socks5://9.8.7.6:1081">Copy</button></td></tr>
		<tr><td><strong class="font-mono">9.9.9.9</strong></td><td class="p-2">9000</td><td>HTTP</td><td><button data-copy="http://9.9.9.9:8000">Copy</button></td></tr>
	</tbody></table>`

	result := parseFlamingoProxiesTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80", "2.3.4.5:443"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"9.8.7.6:1081"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseIPRoyalHelpersExtractComponentAndAPIConfig(t *testing.T) {
	t.Parallel()

	html := `<astro-island component-url="/_astro/FreeProxyListTable.abc123.js"></astro-island>`
	componentURL, err := parseIPRoyalComponentURL(html)
	if err != nil {
		t.Fatalf("parseIPRoyalComponentURL error: %v", err)
	}
	if componentURL != "https://iproyal.com/_astro/FreeProxyListTable.abc123.js" {
		t.Fatalf("unexpected component URL: %q", componentURL)
	}

	baseURL, token, err := parseIPRoyalAPIConfig(`const cfg={Pt="https://cms.iproyal.com",Authorization:"Bearer token-123"};`)
	if err != nil {
		t.Fatalf("parseIPRoyalAPIConfig error: %v", err)
	}
	if baseURL != "https://cms.iproyal.com" {
		t.Fatalf("unexpected base URL: %q", baseURL)
	}
	if token != "token-123" {
		t.Fatalf("unexpected token: %q", token)
	}
}

func TestBuildIPRoyalURLIncludesProtocolAndPagination(t *testing.T) {
	t.Parallel()

	got := buildIPRoyalURL("https://cms.iproyal.com/", "socks5", 3)
	want := "https://cms.iproyal.com/api/free-proxy-records?fields[0]=ip&fields[1]=port&fields[2]=protocol&pagination[page]=3&pagination[pageSize]=100&filters[protocol][$eq]=socks5"
	if got != want {
		t.Fatalf("unexpected URL:\n got: %s\nwant: %s", got, want)
	}
}

func TestParseProxyDBTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr><td><a href="/1.2.3.4/80#http">1.2.3.4</a></td><td><div style="display:none">12</div><a href="/1.2.3.4/80#http">80</a></td><td>HTTP</td></tr>
		<tr><td><a href="/2.3.4.5/443#https">2.3.4.5</a></td><td><div style="display:none">12</div><a href="/2.3.4.5/443#https">443</a></td><td>HTTPS</td></tr>
		<tr><td><a href="/5.6.7.8/1080#socks4">5.6.7.8</a></td><td><div style="display:none">12</div><a href="/5.6.7.8/1080#socks4">1080</a></td><td>SOCKS4</td></tr>
		<tr><td><a href="/9.8.7.6/1081#socks5">9.8.7.6</a></td><td><div style="display:none">12</div><a href="/9.8.7.6/1081#socks5">1081</a></td><td>SOCKS5</td></tr>
		<tr><td><a href="/999.1.1.1/70000#socks5">999.1.1.1</a></td><td><div style="display:none">12</div><a href="/999.1.1.1/70000#socks5">70000</a></td><td>SOCKS5</td></tr>
	</tbody></table>`

	result := parseProxyDBTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80", "2.3.4.5:443"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"9.8.7.6:1081"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseProxyNovaTableDecodesObfuscatedIPs(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr data-proxy-id="1"><td align="left"><script>document.write("31.27.651.83".split("").reverse().join(""))</script></td><td align="left"><a href="/proxy-server-list/port-8080/">8080</a></td></tr>
		<tr data-proxy-id="2"><td align="left"><script>document.write(atob("OTEuMjA0LjE5MC4x").concat("404".substring(0+0, 4-2)))</script></td><td align="left">80</td></tr>
		<tr data-proxy-id="3"><td align="left"><script>document.write([65,64,54].map((code) => String.fromCharCode(code-8)).join("").concat(".46".split("").reverse().join("")).concat("128.182".repeat(2).substring(7)))</script></td><td align="left">1080</td></tr>
		<tr data-proxy-id="4"><td align="left"><script>document.write("999.1.1.1")</script></td><td align="left">8080</td></tr>
	</tbody></table>`

	result := parseProxyNovaTable(html)
	if !slices.Equal(result.HTTP, []string{"38.156.72.13:8080", "91.204.190.140:80", "98.64.128.182:1080"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if len(result.SOCKS4) != 0 {
		t.Fatalf("expected no SOCKS4 proxies, got %v", result.SOCKS4)
	}
	if len(result.SOCKS5) != 0 {
		t.Fatalf("expected no SOCKS5 proxies, got %v", result.SOCKS5)
	}
}

func TestParseFreeProxyWorldTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr>
			<td style="font-weight: 500;">1.2.3.4</td>
			<td><a href="/?port=80">80</a></td>
			<td>United States</td>
			<td>New York</td>
			<td>100 ms</td>
			<td><a href="/?type=http" class="badge badge-warning">http</a><a href="/?type=https" class="badge badge-info">https</a></td>
			<td>No</td>
			<td>2 minutes</td>
		</tr>
		<tr>
			<td style="font-weight: 500;">5.6.7.8</td>
			<td><a href="/?port=1080">1080</a></td>
			<td>Germany</td>
			<td>Berlin</td>
			<td>150 ms</td>
			<td><a href="/?type=socks4" class="badge badge-primary">socks4</a><a href="/?type=socks5" class="badge badge-success">socks5</a></td>
			<td>High</td>
			<td>1 minute</td>
		</tr>
		<tr>
			<td style="font-weight: 500;">999.1.1.1</td>
			<td><a href="/?port=70000">70000</a></td>
			<td>Nowhere</td>
			<td>NA</td>
			<td>999 ms</td>
			<td><a href="/?type=socks5" class="badge badge-success">socks5</a></td>
			<td>No</td>
			<td>never</td>
		</tr>
	</tbody></table>`

	result := parseFreeProxyWorldTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseFreeProxyUpdateTableCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr>
			<td>1.2.3.4</td>
			<td>80</td>
			<td><a href="/us-us">United States</a></td>
			<td><a href="/http-proxy">http</a></td>
			<td><a href="/elite-proxy">elite</a></td>
		</tr>
		<tr>
			<td>2.3.4.5</td>
			<td>443</td>
			<td><a href="/de-de">Germany</a></td>
			<td><a href="/https-ssl-proxy">https</a></td>
			<td><a href="/anonymous-proxy">anonymous</a></td>
		</tr>
		<tr>
			<td>5.6.7.8</td>
			<td>1080</td>
			<td><a href="/fr-fr">France</a></td>
			<td><a href="/socks4-proxy">socks4</a></td>
			<td><a href="/anonymous-proxy">anonymous</a></td>
		</tr>
		<tr>
			<td>9.8.7.6</td>
			<td>1081</td>
			<td><a href="/jp-jp">Japan</a></td>
			<td><a href="/socks5-proxy">socks5</a></td>
			<td><a href="/transparent-proxy">transparent</a></td>
		</tr>
		<tr>
			<td>999.1.1.1</td>
			<td>70000</td>
			<td><a href="/na">Nowhere</a></td>
			<td><a href="/socks5-proxy">socks5</a></td>
			<td><a href="/transparent-proxy">transparent</a></td>
		</tr>
	</tbody></table>`

	result := parseFreeProxyUpdateTable(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80", "2.3.4.5:443"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if !slices.Equal(result.SOCKS4, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"9.8.7.6:1081"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseSpysOnePageCategorizesProtocols(t *testing.T) {
	t.Parallel()

	html := `<script type="text/javascript">a1=1111;b2=2222;c3=0^a1;d4=8^b2;e5=1^a1;</script>
	<table><tbody>
		<tr class=spy1xx>
			<td colspan=1><font class=spy14>1.2.3.4<script type="text/javascript">document.write("<font class=spy2>:</font>"+(d4^b2)+(c3^a1))</script></font></td>
			<td colspan=1><a href='/en/http-proxy-list/'><font class=spy1>HTTP</font></a></td>
		</tr>
		<tr class=spy1x>
			<td colspan=1><font class=spy14>5.6.7.8<script type="text/javascript">document.write("<font class=spy2>:</font>"+(e5^a1)+(c3^a1)+(d4^b2)+(c3^a1))</script></font></td>
			<td colspan=1>SOCKS5</td>
		</tr>
	</tbody></table>`

	result := parseSpysOnePage(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if len(result.SOCKS4) != 0 {
		t.Fatalf("expected no SOCKS4 proxies, got %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"5.6.7.8:1080"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseSpysOnePageIgnoresInvalidRows(t *testing.T) {
	t.Parallel()

	html := `<script type="text/javascript">a1=1111;b2=2222;c3=0^a1;d4=8^b2;</script>
	<table><tbody>
		<tr class=spy1xx>
			<td colspan=1><font class=spy14>999.1.1.1<script type="text/javascript">document.write("<font class=spy2>:</font>"+(d4^b2)+(c3^a1))</script></font></td>
			<td colspan=1>SOCKS4</td>
		</tr>
		<tr class=spy1x>
			<td colspan=1><font class=spy14>8.8.8.8<script type="text/javascript">document.write("<font class=spy2>:</font>"+(missing^b2)+(c3^a1))</script></font></td>
			<td colspan=1>SOCKS5</td>
		</tr>
	</tbody></table>`

	result := parseSpysOnePage(html)
	if result.Total() != 0 {
		t.Fatalf("expected invalid rows to be ignored, got %+v", result)
	}
}

func TestParseSocksProxyNetTableCategorizesVersions(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr><td>1.2.3.4</td><td>1080</td><td>US</td><td class='hm'>United States</td><td>Socks4</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
		<tr><td>5.6.7.8</td><td>1081</td><td>DE</td><td class='hm'>Germany</td><td>Socks5</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
	</tbody></table>`

	result := parseSocksProxyNetTable(html)
	if !slices.Equal(result.SOCKS4, []string{"1.2.3.4:1080"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"5.6.7.8:1081"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
	if len(result.HTTP) != 0 {
		t.Fatalf("expected no HTTP proxies, got %v", result.HTTP)
	}
}

func TestParseSocksProxyNetTableIgnoresInvalidRows(t *testing.T) {
	t.Parallel()

	html := `<table><tbody>
		<tr><td>999.1.1.1</td><td>1080</td><td>US</td><td class='hm'>United States</td><td>Socks4</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
		<tr><td>1.2.3.4</td><td>70000</td><td>US</td><td class='hm'>United States</td><td>Socks5</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
		<tr><td>9.8.7.6</td><td>1080</td><td>US</td><td class='hm'>United States</td><td>HTTP</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
		<tr><td>8.8.8.8</td><td>1080</td><td>US</td><td class='hm'>United States</td><td>sOcKs5</td><td class='hm'>Anonymous</td><td class='hm'>Yes</td><td class='hd'>2 mins ago</td></tr>
	</tbody></table>`

	result := parseSocksProxyNetTable(html)
	if len(result.SOCKS4) != 0 {
		t.Fatalf("expected invalid SOCKS4 row to be ignored, got %v", result.SOCKS4)
	}
	if !slices.Equal(result.SOCKS5, []string{"8.8.8.8:1080"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", result.SOCKS5)
	}
}

func TestParseProxyListOrgPageDecodesBase64Entries(t *testing.T) {
	t.Parallel()

	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	html := "<ul>" +
		"<li><script>Proxy('" + enc("1.2.3.4:80") + "')</script></li>" +
		"<li><script>Proxy('" + enc("5.6.7.8:8080") + "')</script></li>" +
		"<li><script>Proxy('" + enc("not-an-address") + "')</script></li>" +
		"<li><script>Proxy('!!!not-base64!!!')</script></li>" +
		"</ul>"

	result := parseProxyListOrgPage(html)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:80", "5.6.7.8:8080"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if len(result.SOCKS4) != 0 || len(result.SOCKS5) != 0 {
		t.Fatalf("expected no SOCKS proxies, got %+v", result)
	}
}

func TestParseProxyListPlusPageCategorizesByRow(t *testing.T) {
	t.Parallel()

	httpHTML := `<table>
		<tr class="cells" onMouseOver="this.className='cells2'" onMouseOut="this.className='cells'">
			<td><img src="/flags/us.png" alt="" /></td>
			<td>1.2.3.4</td>
			<td>8080</td>
			<td>transparent</td>
			<td>United States</td>
		</tr>
		<tr class="cells" onMouseOver="this.className='cells2'" onMouseOut="this.className='cells'">
			<td><img src="/flags/de.png" alt="" /></td>
			<td>5.6.7.8</td>
			<td>3128</td>
			<td>elite</td>
			<td>Germany</td>
		</tr>
	</table>`

	result := parseProxyListPlusPage(httpHTML, models.ProxyTypeHTTP)
	if !slices.Equal(result.HTTP, []string{"1.2.3.4:8080", "5.6.7.8:3128"}) {
		t.Fatalf("unexpected HTTP proxies: %v", result.HTTP)
	}
	if len(result.SOCKS4) != 0 || len(result.SOCKS5) != 0 {
		t.Fatalf("expected no SOCKS proxies, got %+v", result)
	}

	socksHTML := `<table>
		<tr class="cells" onMouseOver="this.className='cells2'" onMouseOut="this.className='cells'">
			<td><img src="/flags/br.png" alt="" /></td>
			<td>9.8.7.6</td>
			<td>35759</td>
			<td>Socks4</td>
			<td>Brazil</td>
		</tr>
		<tr class="cells" onMouseOver="this.className='cells2'" onMouseOut="this.className='cells'">
			<td><img src="/flags/us.png" alt="" /></td>
			<td>4.3.2.1</td>
			<td>45554</td>
			<td>Socks5</td>
			<td>United States</td>
		</tr>
	</table>`

	socksResult := parseProxyListPlusPage(socksHTML, models.ProxyTypeSOCKS5)
	if !slices.Equal(socksResult.SOCKS4, []string{"9.8.7.6:35759"}) {
		t.Fatalf("unexpected SOCKS4 proxies: %v", socksResult.SOCKS4)
	}
	if !slices.Equal(socksResult.SOCKS5, []string{"4.3.2.1:45554"}) {
		t.Fatalf("unexpected SOCKS5 proxies: %v", socksResult.SOCKS5)
	}
	if len(socksResult.HTTP) != 0 {
		t.Fatalf("expected no HTTP proxies, got %v", socksResult.HTTP)
	}
}
