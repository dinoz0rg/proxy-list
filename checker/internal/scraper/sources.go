package scraper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"proxies-checker/internal/models"
)

var ipPortRe = regexp.MustCompile(`(?:^|\D)((?:\d{1,3}\.){3}\d{1,3}:\d{2,5})(?:\D|$)`)

var socksProxyNetRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>\s*<td>[^<]*</td>\s*<td[^>]*>[^<]*</td>\s*<td>(socks[45])</td>`)

var advancedNameRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td>\d+</td>\s*<td[^>]*data-ip="([^"]+)"[^>]*></td>\s*<td[^>]*data-port="([^"]+)"[^>]*></td>\s*<td>(.*?)</td>`)

var hideMnRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td>((?:\d{1,3}\.){3}\d{1,3})</td>\s*<td>(\d{2,5})</td>\s*<td>.*?</td>\s*<td>.*?</td>\s*<td>(.*?)</td>`)

var protocolCellPattern = regexp.MustCompile(`(?i)\bhttps?\b|\bsocks[45]\b`)

var freeProxyWorldRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td[^>]*>((?:\d{1,3}\.){3}\d{1,3})</td>\s*<td>\s*<a[^>]*>(\d{2,5})</a>\s*</td>\s*<td>.*?</td>\s*<td>.*?</td>\s*<td>.*?</td>\s*<td>(.*?)</td>`)

var freeProxyUpdateRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td>((?:\d{1,3}\.){3}\d{1,3})</td>\s*<td>(\d{2,5})</td>\s*<td>.*?</td>\s*<td><a [^>]*>(https?|socks[45])</a></td>`)

var htmlTagPattern = regexp.MustCompile(`(?is)<[^>]+>`)

var ipRoyalComponentURLPattern = regexp.MustCompile(`component-url="([^"]*FreeProxyListTable[^"]+)"`)

var ipRoyalBaseURLPattern = regexp.MustCompile(`Pt="([^"]+)"`)

var ipRoyalAuthTokenPattern = regexp.MustCompile(`Authorization:"Bearer ([^"]+)"`)

var flamingoProxyRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td><strong[^>]*>((?:\d{1,3}\.){3}\d{1,3})</strong></td>\s*<td[^>]*>(\d{2,5})</td>.*?<button[^>]*data-copy="([^"]+)"`)

var spysOneScriptPattern = regexp.MustCompile(`(?is)<script type="text/javascript">([a-z0-9=^;]+)</script>`)

var spysOneAssignmentPattern = regexp.MustCompile(`^([a-z][a-z0-9]*)=(.+)$`)

var spysOneRowPattern = regexp.MustCompile(`(?is)<tr class=spy1xx?[^>]*>\s*<td[^>]*><font class=spy14>((?:\d{1,3}\.){3}\d{1,3})<script type="text/javascript">document\.write\(".*?"\+(.+?)\)</script></font></td>\s*<td[^>]*>(.*?)</td>`)

var proxyDBRowPattern = regexp.MustCompile(`(?is)<tr>\s*<td><a [^>]*>((?:\d{1,3}\.){3}\d{1,3})</a></td>\s*<td>(?:<div[^>]*>.*?</div>\s*)?<a [^>]*>(\d{2,5})</a></td>\s*<td>(https?|socks[45])</td>`)

var proxyNovaRowPattern = regexp.MustCompile(`(?is)<tr data-proxy-id="[^"]+">\s*<td[^>]*>\s*<script>document\.write\((.*?)\)</script>\s*</td>\s*<td[^>]*>\s*(?:<a[^>]*>)?(\d{2,5})(?:</a>)?`)

var proxyNovaCharCodePattern = regexp.MustCompile(`^\[(\d+(?:\s*,\s*\d+)*)]\.map\(\(code\)\s*=>\s*String\.fromCharCode\(code\s*([+-])\s*(\d+)\)\)\.join\(""\)`)

var proxyListOrgEntryPattern = regexp.MustCompile(`Proxy\('([A-Za-z0-9+/=]+)'\)`)

var proxyListPlusRowPattern = regexp.MustCompile(`(?is)<tr class="cells" onMouseOver[^>]*>\s*<td>[^<]*<img[^>]*/>[^<]*</td>\s*<td>\s*((?:\d{1,3}\.){3}\d{1,3})\s*</td>\s*<td>\s*(\d{2,5})\s*</td>\s*<td>\s*([^<]*?)\s*</td>`)

const (
	githubFetchConcurrency = 6
	allSourcesConcurrency  = 4
)

// parseLines splits text into non-empty trimmed lines.
func parseLines(text string) []string {
	var lines []string
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func parseIPPortMatches(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range ipPortRe.FindAllStringSubmatch(text, -1) {
		result.AppendByType(models.ProxyTypeHTTP, match[1])
	}
	return result
}

// --- FreeProxyList ---

type FreeProxyListSource struct{}

func (s *FreeProxyListSource) Name() string { return "FreeProxyList" }

func (s *FreeProxyListSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range freeProxyListPages {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch page", "source", "FreeProxyList", "url", url, "err", err)
			continue
		}
		result.Merge(parseIPPortMatches(text))
	}
	return result, nil
}

// --- AnonymousProxy ---

type AnonymousProxySource struct{}

func (s *AnonymousProxySource) Name() string { return "AnonymousProxy" }

func (s *AnonymousProxySource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, anonymousProxyURL)
	if err != nil {
		return nil, err
	}
	return parseIPPortMatches(text), nil
}

// --- UKProxy ---

type UKProxySource struct{}

func (s *UKProxySource) Name() string { return "UKProxy" }

func (s *UKProxySource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, ukProxyURL)
	if err != nil {
		return nil, err
	}
	return parseIPPortMatches(text), nil
}

// --- GeoNode ---

type GeoNodeSource struct{}

func (s *GeoNodeSource) Name() string { return "GeoNode" }

func (s *GeoNodeSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	const baseURL = "https://proxylist.geonode.com/api/proxy-list"
	const pageSize = 500
	result := &models.ProxyResult{}

	for page := 1; ; page++ {
		url := fmt.Sprintf("%s?limit=%d&page=%d", baseURL, pageSize, page)
		text, err := httpGet(ctx, url)
		if err != nil {
			return result, fmt.Errorf("fetching page %d: %w", page, err)
		}

		var data struct {
			Data []struct {
				IP        string   `json:"ip"`
				Port      string   `json:"port"`
				Protocols []string `json:"protocols"`
			} `json:"data"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal([]byte(text), &data); err != nil {
			return result, fmt.Errorf("parsing JSON: %w", err)
		}

		for _, p := range data.Data {
			if p.IP == "" || p.Port == "" {
				continue
			}
			addr := p.IP + ":" + p.Port
			for _, proto := range p.Protocols {
				switch strings.ToLower(proto) {
				case models.ProxyTypeHTTP.String(), "https":
					result.AppendByType(models.ProxyTypeHTTP, addr)
				case models.ProxyTypeSOCKS4.String():
					result.AppendByType(models.ProxyTypeSOCKS4, addr)
				case models.ProxyTypeSOCKS5.String():
					result.AppendByType(models.ProxyTypeSOCKS5, addr)
				}
			}
		}

		if page*pageSize >= data.Total {
			break
		}
	}
	return result, nil
}

// --- GitHub ---

type GitHubSource struct{}

func (s *GitHubSource) Name() string { return "GitHub" }

func (s *GitHubSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := make(chan struct{}, githubFetchConcurrency)
	result := &models.ProxyResult{}

	for proxyType, urls := range githubSources {
		for _, url := range urls {
			wg.Go(func() {
				select {
				case limit <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-limit }()

				text, err := httpGet(ctx, url)
				if err != nil {
					slog.Warn("Failed to fetch", "source", "GitHub", "url", url, "err", err)
					return
				}
				lines := parseLines(text)
				mu.Lock()
				defer mu.Unlock()
				categorize(lines, proxyType, result)
			})
		}
	}
	wg.Wait()
	return result, nil
}

func categorize(lines []string, proxyType models.ProxyType, result *models.ProxyResult) {
	if proxyType == models.ProxyTypeAll {
		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeHTTP)); ok {
				result.AppendByType(models.ProxyTypeHTTP, after)
			} else if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeSOCKS4)); ok {
				result.AppendByType(models.ProxyTypeSOCKS4, after)
			} else if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeSOCKS5)); ok {
				result.AppendByType(models.ProxyTypeSOCKS5, after)
			}
		}
		return
	}
	result.AppendByType(proxyType, lines...)
}

// --- MyProxy ---

type MyProxySource struct{}

func (s *MyProxySource) Name() string { return "MyProxy" }

func (s *MyProxySource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for proxyType, url := range myProxySources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "MyProxy", "url", url, "err", err)
			continue
		}
		for _, match := range myProxyPattern.FindAllStringSubmatch(text, -1) {
			result.AppendByType(proxyType, match[1])
		}
	}
	return result, nil
}

// --- OpenProxyList ---

type OpenProxyListSource struct{}

func (s *OpenProxyListSource) Name() string { return "OpenProxyList" }

func (s *OpenProxyListSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for proxyType, url := range openProxyListSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "OpenProxyList", "url", url, "err", err)
			continue
		}
		result.AppendByType(proxyType, parseLines(text)...)
	}
	return result, nil
}

// --- Proxy5050 ---

type Proxy5050Source struct{}

func (s *Proxy5050Source) Name() string { return "Proxy5050" }

func (s *Proxy5050Source) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, proxy5050URL)
	if err != nil {
		return nil, err
	}
	result := &models.ProxyResult{}
	for _, match := range ipPortRe.FindAllStringSubmatch(text, -1) {
		result.AppendByType(models.ProxyTypeHTTP, match[1])
	}
	return result, nil
}

// --- ProxyScrape ---

type ProxyScrapeSource struct{}

func (s *ProxyScrapeSource) Name() string { return "ProxyScrape" }

func (s *ProxyScrapeSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, proxyScrapeURL)
	if err != nil {
		return nil, err
	}
	result := &models.ProxyResult{}
	for _, line := range parseLines(text) {
		if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeHTTP)); ok {
			result.AppendByType(models.ProxyTypeHTTP, after)
		} else if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeSOCKS4)); ok {
			result.AppendByType(models.ProxyTypeSOCKS4, after)
		} else if after, ok := strings.CutPrefix(line, models.ProtocolPrefix(models.ProxyTypeSOCKS5)); ok {
			result.AppendByType(models.ProxyTypeSOCKS5, after)
		}
	}
	return result, nil
}

// --- ProxySpace ---

type ProxySpaceSource struct{}

func (s *ProxySpaceSource) Name() string { return "ProxySpace" }

func (s *ProxySpaceSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for proxyType, url := range proxySpaceSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "ProxySpace", "url", url, "err", err)
			continue
		}
		result.AppendByType(proxyType, parseLines(text)...)
	}
	return result, nil
}

// --- SpysMe ---

type SpysMeSource struct{}

func (s *SpysMeSource) Name() string { return "SpysMe" }

func (s *SpysMeSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	httpText, err1 := httpGet(ctx, spysMeHTTPURL)
	socksText, err2 := httpGet(ctx, spysMeSOCKSURL)
	if err1 != nil && err2 != nil {
		return nil, errors.Join(err1, err2)
	}

	result := &models.ProxyResult{}
	if err1 == nil {
		result.AppendByType(models.ProxyTypeHTTP, parseSpysMeLines(httpText)...)
	}
	// SpysMe socks.txt does not distinguish between SOCKS4 and SOCKS5,
	// so we add the same proxies to both lists and let the checker filter.
	if err2 == nil {
		socksProxies := parseSpysMeLines(socksText)
		result.AppendByType(models.ProxyTypeSOCKS4, socksProxies...)
		result.AppendByType(models.ProxyTypeSOCKS5, socksProxies...)
	}
	return result, nil
}

func parseSpysMeLines(text string) []string {
	var result []string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if candidate, ok := models.NormalizeProxyAddr(fields[0]); ok {
			result = append(result, candidate)
		}
	}
	return result
}

// --- ProxyDB ---

type ProxyDBSource struct{}

func (s *ProxyDBSource) Name() string { return "ProxyDB" }

func (s *ProxyDBSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range proxyDBSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "ProxyDB", "url", url, "err", err)
			continue
		}
		result.Merge(parseProxyDBTable(text))
	}
	return result, nil
}

func parseProxyDBTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range proxyDBRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		switch strings.ToLower(strings.TrimSpace(match[3])) {
		case models.ProxyTypeHTTP.String(), "https":
			result.AppendByType(models.ProxyTypeHTTP, addr)
		case models.ProxyTypeSOCKS4.String():
			result.AppendByType(models.ProxyTypeSOCKS4, addr)
		case models.ProxyTypeSOCKS5.String():
			result.AppendByType(models.ProxyTypeSOCKS5, addr)
		}
	}
	return result
}

// --- ProxyNova ---

type ProxyNovaSource struct{}

func (s *ProxyNovaSource) Name() string { return "ProxyNova" }

func (s *ProxyNovaSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, proxyNovaURL)
	if err != nil {
		return nil, err
	}
	return parseProxyNovaTable(text), nil
}

func parseProxyNovaTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range proxyNovaRowPattern.FindAllStringSubmatch(text, -1) {
		ip, ok := evalProxyNovaExpression(match[1])
		if !ok {
			continue
		}
		result.AppendByType(models.ProxyTypeHTTP, ip+":"+strings.TrimSpace(match[2]))
	}
	return result
}

func evalProxyNovaExpression(expression string) (string, bool) {
	parser := proxyNovaParser{input: strings.TrimSpace(expression)}
	value, ok := parser.parseString()
	if !ok {
		return "", false
	}
	parser.skipSpaces()
	if parser.pos != len(parser.input) {
		return "", false
	}
	return value, true
}

type proxyNovaParser struct {
	input string
	pos   int
}

func (p *proxyNovaParser) parseString() (string, bool) {
	value, ok := p.parsePrimary()
	if !ok {
		return "", false
	}

	for {
		p.skipSpaces()
		switch {
		case p.consume(`.split("")`):
			if !p.consume(`.reverse()`) || !p.consume(`.join("")`) {
				return "", false
			}
			value = reverseString(value)
		case p.consume(`.repeat(`):
			repeatCount, ok := p.parseIntUntil(')')
			if !ok || !p.consume(")") || repeatCount < 0 {
				return "", false
			}
			value = strings.Repeat(value, repeatCount)
		case p.consume(`.substring(`):
			start, ok := p.parseIntUntil(',', ')')
			if !ok {
				return "", false
			}
			end := len(value)
			p.skipSpaces()
			if p.peek() == ',' {
				p.pos++
				endValue, ok := p.parseIntUntil(')')
				if !ok {
					return "", false
				}
				end = endValue
			}
			if !p.consume(")") {
				return "", false
			}
			value = proxyNovaSubstring(value, start, end)
		case p.consume(`.concat(`):
			part, ok := p.parseString()
			if !ok || !p.consume(")") {
				return "", false
			}
			value += part
		default:
			return value, true
		}
	}
}

func (p *proxyNovaParser) parsePrimary() (string, bool) {
	p.skipSpaces()
	remaining := p.input[p.pos:]

	if match := proxyNovaCharCodePattern.FindStringSubmatch(remaining); len(match) == 4 {
		p.pos += len(match[0])
		return buildProxyNovaChars(match[1], match[2], match[3])
	}

	if p.consume("atob(") {
		literal, ok := p.parseQuotedString()
		if !ok || !p.consume(")") {
			return "", false
		}
		decoded, err := decodeBase64Text(literal)
		if err != nil {
			return "", false
		}
		return decoded, true
	}

	if p.peek() == '"' {
		return p.parseQuotedString()
	}

	return "", false
}

func (p *proxyNovaParser) parseQuotedString() (string, bool) {
	if p.peek() != '"' {
		return "", false
	}

	start := p.pos
	p.pos++
	escaped := false
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		p.pos++
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			value, err := strconv.Unquote(p.input[start:p.pos])
			if err != nil {
				return "", false
			}
			return value, true
		}
	}
	return "", false
}

func (p *proxyNovaParser) parseIntUntil(delimiters ...byte) (int, bool) {
	p.skipSpaces()
	start := p.pos
	for p.pos < len(p.input) {
		if slices.Contains(delimiters, p.input[p.pos]) {
			break
		}
		p.pos++
	}
	if start == p.pos {
		return 0, false
	}
	return evalProxyNovaIntExpr(p.input[start:p.pos])
}

func (p *proxyNovaParser) skipSpaces() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\n', '\r', '\t':
			p.pos++
		default:
			return
		}
	}
}

func (p *proxyNovaParser) consume(prefix string) bool {
	p.skipSpaces()
	if !strings.HasPrefix(p.input[p.pos:], prefix) {
		return false
	}
	p.pos += len(prefix)
	return true
}

func (p *proxyNovaParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func buildProxyNovaChars(rawNumbers, operator, rawOffset string) (string, bool) {
	offset, err := strconv.Atoi(rawOffset)
	if err != nil {
		return "", false
	}

	var builder strings.Builder
	for part := range strings.SplitSeq(rawNumbers, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return "", false
		}
		if operator == "+" {
			value += offset
		} else {
			value -= offset
		}
		builder.WriteRune(rune(value))
	}
	return builder.String(), true
}

func reverseString(value string) string {
	bytes := []byte(value)
	slices.Reverse(bytes)
	return string(bytes)
}

func evalProxyNovaIntExpr(expression string) (int, bool) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return 0, false
	}

	var total int
	var current strings.Builder
	op := byte('+')
	flush := func() bool {
		if current.Len() == 0 {
			return false
		}
		value, err := strconv.Atoi(current.String())
		if err != nil {
			return false
		}
		if op == '+' {
			total += value
		} else {
			total -= value
		}
		current.Reset()
		return true
	}

	for i := range len(expression) {
		switch ch := expression[i]; {
		case ch >= '0' && ch <= '9':
			current.WriteByte(ch)
		case ch == '+' || ch == '-':
			if !flush() {
				return 0, false
			}
			op = ch
		case ch == ' ' || ch == '\t':
			continue
		default:
			return 0, false
		}
	}
	if !flush() {
		return 0, false
	}
	return total, true
}

func proxyNovaSubstring(value string, start, end int) string {
	start = max(start, 0)
	end = max(end, 0)
	start = min(start, len(value))
	end = min(end, len(value))
	if start > end {
		start, end = end, start
	}
	return value[start:end]
}

// --- Databay ---

type DatabaySource struct{}

func (s *DatabaySource) Name() string { return "Databay" }

func (s *DatabaySource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, request := range databayRequests {
		proxies, err := fetchDatabayProtocol(ctx, request.protocol)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "Databay", "protocol", request.protocol, "err", err)
			continue
		}
		result.AppendByType(request.proxyType, proxies...)
	}
	return result, nil
}

func fetchDatabayProtocol(ctx context.Context, protocol string) ([]string, error) {
	var proxies []string
	for page := 1; page <= databayMaxPages; page++ {
		url := fmt.Sprintf("%s?protocol=%s&format=txt&limit=%d&page=%d", databayBaseURL, protocol, databayPageSize, page)
		text, err := httpGet(ctx, url)
		if err != nil {
			return proxies, err
		}

		pageProxies := parseLines(text)
		if len(pageProxies) == 0 {
			break
		}
		proxies = append(proxies, pageProxies...)
		if len(pageProxies) < databayPageSize {
			break
		}
	}
	return proxies, nil
}

// --- SocksProxyNet ---

type SocksProxyNetSource struct{}

func (s *SocksProxyNetSource) Name() string { return "SocksProxyNet" }

func (s *SocksProxyNetSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, socksProxyNetURL)
	if err != nil {
		return nil, err
	}
	return parseSocksProxyNetTable(text), nil
}

func parseSocksProxyNetTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range socksProxyNetRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		switch strings.ToLower(strings.TrimSpace(match[3])) {
		case models.ProxyTypeSOCKS4.String():
			result.AppendByType(models.ProxyTypeSOCKS4, addr)
		case models.ProxyTypeSOCKS5.String():
			result.AppendByType(models.ProxyTypeSOCKS5, addr)
		}
	}
	return result
}

// --- AdvancedName ---

type AdvancedNameSource struct{}

func (s *AdvancedNameSource) Name() string { return "AdvancedName" }

func (s *AdvancedNameSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range advancedNameSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "AdvancedName", "url", url, "err", err)
			continue
		}
		result.Merge(parseAdvancedNameTable(text))
	}
	return result, nil
}

func parseAdvancedNameTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range advancedNameRowPattern.FindAllStringSubmatch(text, -1) {
		ip, err := decodeBase64Text(match[1])
		if err != nil {
			continue
		}
		port, err := decodeBase64Text(match[2])
		if err != nil {
			continue
		}

		addr := ip + ":" + port
		appendByDetectedProtocols(result, addr, match[3])
	}
	return result
}

func decodeBase64Text(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// --- HideMn ---

type HideMnSource struct{}

func (s *HideMnSource) Name() string { return "HideMn" }

func (s *HideMnSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, hideMnURL)
	if err != nil {
		return nil, err
	}
	return parseHideMnTable(text), nil
}

func parseHideMnTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range hideMnRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		appendByDetectedProtocols(result, addr, match[3])
	}
	return result
}

func appendByDetectedProtocols(result *models.ProxyResult, addr, protocolCell string) {
	protocolCell = stripHTMLTags(protocolCell)
	hasHTTP := false
	hasSOCKS4 := false
	hasSOCKS5 := false
	for _, token := range protocolCellPattern.FindAllString(protocolCell, -1) {
		switch strings.ToLower(strings.TrimSpace(token)) {
		case models.ProxyTypeHTTP.String(), "https":
			hasHTTP = true
		case models.ProxyTypeSOCKS4.String():
			hasSOCKS4 = true
		case models.ProxyTypeSOCKS5.String():
			hasSOCKS5 = true
		}
	}
	if hasHTTP {
		result.AppendByType(models.ProxyTypeHTTP, addr)
	}
	if hasSOCKS4 {
		result.AppendByType(models.ProxyTypeSOCKS4, addr)
	}
	if hasSOCKS5 {
		result.AppendByType(models.ProxyTypeSOCKS5, addr)
	}
}

func stripHTMLTags(value string) string {
	value = htmlTagPattern.ReplaceAllString(value, " ")
	return strings.Join(strings.Fields(value), " ")
}

func firstSubmatch(pattern *regexp.Regexp, text string) (string, bool) {
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return "", false
	}
	return strings.TrimSpace(match[1]), true
}

func buildIPRoyalURL(baseURL, protocol string, page int) string {
	return fmt.Sprintf(
		"%s/api/free-proxy-records?fields[0]=ip&fields[1]=port&fields[2]=protocol&pagination[page]=%d&pagination[pageSize]=%d&filters[protocol][$eq]=%s",
		strings.TrimRight(baseURL, "/"),
		page,
		ipRoyalPageSize,
		protocol,
	)
}

func mapProtocolLabel(label string) (models.ProxyType, bool) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case models.ProxyTypeHTTP.String(), "https":
		return models.ProxyTypeHTTP, true
	case models.ProxyTypeSOCKS4.String():
		return models.ProxyTypeSOCKS4, true
	case models.ProxyTypeSOCKS5.String():
		return models.ProxyTypeSOCKS5, true
	default:
		return "", false
	}
}

func extractCopyAddress(raw string) (string, bool) {
	_, addr, ok := strings.Cut(strings.TrimSpace(raw), "://")
	if !ok || addr == "" {
		return "", false
	}
	return addr, true
}

// --- IPRoyal ---

type IPRoyalSource struct{}

func (s *IPRoyalSource) Name() string { return "IPRoyal" }

func (s *IPRoyalSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	baseURL, token, err := fetchIPRoyalConfig(ctx)
	if err != nil {
		return nil, err
	}

	result := &models.ProxyResult{}
	for _, request := range ipRoyalRequests {
		proxies, err := fetchIPRoyalProtocol(ctx, baseURL, token, request.protocol)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "IPRoyal", "protocol", request.protocol, "err", err)
			continue
		}
		result.AppendByType(request.proxyType, proxies...)
	}
	return result, nil
}

func fetchIPRoyalConfig(ctx context.Context) (string, string, error) {
	html, err := httpGet(ctx, ipRoyalFreeProxyListURL)
	if err != nil {
		return "", "", err
	}

	componentURL, err := parseIPRoyalComponentURL(html)
	if err != nil {
		return "", "", err
	}

	componentJS, err := httpGet(ctx, componentURL)
	if err != nil {
		return "", "", err
	}

	return parseIPRoyalAPIConfig(componentJS)
}

func parseIPRoyalComponentURL(html string) (string, error) {
	componentPath, ok := firstSubmatch(ipRoyalComponentURLPattern, html)
	if !ok {
		return "", errors.New("IPRoyal component URL not found")
	}
	return "https://iproyal.com" + strings.TrimSpace(componentPath), nil
}

func parseIPRoyalAPIConfig(componentJS string) (string, string, error) {
	baseURL, ok := firstSubmatch(ipRoyalBaseURLPattern, componentJS)
	if !ok {
		return "", "", errors.New("IPRoyal API base URL not found")
	}
	token, ok := firstSubmatch(ipRoyalAuthTokenPattern, componentJS)
	if !ok {
		return "", "", errors.New("IPRoyal API token not found")
	}
	return baseURL, token, nil
}

func fetchIPRoyalProtocol(ctx context.Context, baseURL, token, protocol string) ([]string, error) {
	var proxies []string
	headers := map[string]string{"Authorization": "Bearer " + token}

	for page := 1; ; page++ {
		text, err := httpGetWithHeaders(ctx, buildIPRoyalURL(baseURL, protocol, page), headers)
		if err != nil {
			return proxies, err
		}

		var data struct {
			Data []struct {
				IP       string `json:"ip"`
				Port     string `json:"port"`
				Protocol string `json:"protocol"`
			} `json:"data"`
			Meta struct {
				Pagination struct {
					Page      int `json:"page"`
					PageCount int `json:"pageCount"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(text), &data); err != nil {
			return proxies, fmt.Errorf("parsing JSON: %w", err)
		}

		for _, proxy := range data.Data {
			if !strings.EqualFold(proxy.Protocol, protocol) || proxy.IP == "" || proxy.Port == "" {
				continue
			}
			proxies = append(proxies, proxy.IP+":"+proxy.Port)
		}

		if data.Meta.Pagination.PageCount <= page || len(data.Data) == 0 {
			break
		}
	}
	return proxies, nil
}

// --- FlamingoProxies ---

type FlamingoProxiesSource struct{}

func (s *FlamingoProxiesSource) Name() string { return "FlamingoProxies" }

func (s *FlamingoProxiesSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	text, err := httpGet(ctx, flamingoProxiesURL)
	if err != nil {
		return nil, err
	}
	return parseFlamingoProxiesTable(text), nil
}

func parseFlamingoProxiesTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range flamingoProxyRowPattern.FindAllStringSubmatch(text, -1) {
		addr, ok := extractCopyAddress(match[3])
		if !ok || addr != strings.TrimSpace(match[1])+":"+strings.TrimSpace(match[2]) {
			continue
		}
		proxyType, ok := mapProtocolLabel(strings.SplitN(strings.TrimSpace(match[3]), "://", 2)[0])
		if !ok {
			continue
		}
		result.AppendByType(proxyType, addr)
	}
	return result
}

// --- FreeProxyWorld ---

type FreeProxyWorldSource struct{}

func (s *FreeProxyWorldSource) Name() string { return "FreeProxyWorld" }

func (s *FreeProxyWorldSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range freeProxyWorldSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "FreeProxyWorld", "url", url, "err", err)
			continue
		}
		result.Merge(parseFreeProxyWorldTable(text))
	}
	return result, nil
}

func parseFreeProxyWorldTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range freeProxyWorldRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		appendByDetectedProtocols(result, addr, match[3])
	}
	return result
}

// --- FreeProxyUpdate ---

type FreeProxyUpdateSource struct{}

func (s *FreeProxyUpdateSource) Name() string { return "FreeProxyUpdate" }

func (s *FreeProxyUpdateSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range freeProxyUpdateSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "FreeProxyUpdate", "url", url, "err", err)
			continue
		}
		result.Merge(parseFreeProxyUpdateTable(text))
	}
	return result, nil
}

type FreeProxyUpdateFilteredSource struct{}

func (s *FreeProxyUpdateFilteredSource) Name() string { return "FreeProxyUpdateFiltered" }

func (s *FreeProxyUpdateFilteredSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range freeProxyUpdateFilteredSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "FreeProxyUpdateFiltered", "url", url, "err", err)
			continue
		}
		result.Merge(parseFreeProxyUpdateTable(text))
	}
	return result, nil
}

func parseFreeProxyUpdateTable(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range freeProxyUpdateRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		appendByDetectedProtocols(result, addr, match[3])
	}
	return result
}

// --- SpysOne ---

type SpysOneSource struct{}

func (s *SpysOneSource) Name() string { return "SpysOne" }

func (s *SpysOneSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, url := range spysOneSources {
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch", "source", "SpysOne", "url", url, "err", err)
			continue
		}
		result.Merge(parseSpysOnePage(text))
	}
	return result, nil
}

func parseSpysOnePage(text string) *models.ProxyResult {
	values, ok := parseSpysOneVariables(text)
	if !ok {
		return &models.ProxyResult{}
	}

	result := &models.ProxyResult{}
	for _, match := range spysOneRowPattern.FindAllStringSubmatch(text, -1) {
		port, ok := parseSpysOnePort(match[2], values)
		if !ok {
			continue
		}
		addr := strings.TrimSpace(match[1]) + ":" + port
		appendByDetectedProtocols(result, addr, match[3])
	}
	return result
}

func parseSpysOneVariables(text string) (map[string]int, bool) {
	match := spysOneScriptPattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return nil, false
	}

	values := make(map[string]int)
	for statement := range strings.SplitSeq(match[1], ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		parts := spysOneAssignmentPattern.FindStringSubmatch(statement)
		if len(parts) != 3 {
			return nil, false
		}
		value, ok := evalSpysOneExpression(parts[2], values)
		if !ok {
			return nil, false
		}
		values[parts[1]] = value
	}
	return values, true
}

func parseSpysOnePort(expression string, values map[string]int) (string, bool) {
	var builder strings.Builder
	for part := range strings.SplitSeq(expression, "+") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "(")
		part = strings.TrimSuffix(part, ")")
		value, ok := evalSpysOneExpression(part, values)
		if !ok || value < 0 || value > 9 {
			return "", false
		}
		builder.WriteByte(byte('0' + value))
	}
	if builder.Len() == 0 {
		return "", false
	}
	return builder.String(), true
}

func evalSpysOneExpression(expression string, values map[string]int) (int, bool) {
	var value int
	first := true
	for term := range strings.SplitSeq(expression, "^") {
		resolved, ok := resolveSpysOneTerm(strings.TrimSpace(term), values)
		if !ok {
			return 0, false
		}
		if first {
			value = resolved
			first = false
			continue
		}
		value ^= resolved
	}
	return value, !first
}

func resolveSpysOneTerm(term string, values map[string]int) (int, bool) {
	if term == "" {
		return 0, false
	}
	if value, err := strconv.Atoi(term); err == nil {
		return value, true
	}
	value, ok := values[term]
	return value, ok
}

// --- ProxyListOrg ---

type ProxyListOrgSource struct{}

func (s *ProxyListOrgSource) Name() string { return "ProxyListOrg" }

func (s *ProxyListOrgSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for page := 1; page <= proxyListOrgMaxPages; page++ {
		url := proxyListOrgBaseURL
		if page > 1 {
			url = fmt.Sprintf("%s?p=%d", proxyListOrgBaseURL, page)
		}
		text, err := httpGet(ctx, url)
		if err != nil {
			slog.Warn("Failed to fetch page", "source", "ProxyListOrg", "url", url, "err", err)
			continue
		}
		parsed := parseProxyListOrgPage(text)
		if len(parsed.HTTP) == 0 {
			break
		}
		result.Merge(parsed)
	}
	return result, nil
}

func parseProxyListOrgPage(text string) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range proxyListOrgEntryPattern.FindAllStringSubmatch(text, -1) {
		decoded, err := decodeBase64Text(match[1])
		if err != nil {
			continue
		}
		for _, addrMatch := range ipPortRe.FindAllStringSubmatch(decoded, -1) {
			result.AppendByType(models.ProxyTypeHTTP, addrMatch[1])
		}
	}
	return result
}

// --- ProxyListPlus ---

type ProxyListPlusSource struct{}

func (s *ProxyListPlusSource) Name() string { return "ProxyListPlus" }

func (s *ProxyListPlusSource) Fetch(ctx context.Context) (*models.ProxyResult, error) {
	result := &models.ProxyResult{}
	for _, page := range proxyListPlusPages {
		text, err := httpGet(ctx, page.url)
		if err != nil {
			slog.Warn("Failed to fetch page", "source", "ProxyListPlus", "url", page.url, "err", err)
			continue
		}
		result.Merge(parseProxyListPlusPage(text, page.defaultType))
	}
	return result, nil
}

func parseProxyListPlusPage(text string, defaultType models.ProxyType) *models.ProxyResult {
	result := &models.ProxyResult{}
	for _, match := range proxyListPlusRowPattern.FindAllStringSubmatch(text, -1) {
		addr := strings.TrimSpace(match[1]) + ":" + strings.TrimSpace(match[2])
		proxyType := defaultType
		switch strings.ToLower(strings.TrimSpace(match[3])) {
		case "socks4":
			proxyType = models.ProxyTypeSOCKS4
		case "socks5":
			proxyType = models.ProxyTypeSOCKS5
		}
		result.AppendByType(proxyType, addr)
	}
	return result
}

// AllSources returns all available proxy sources.
func AllSources() []Source {
	return []Source{
		&AdvancedNameSource{},
		&AnonymousProxySource{},
		&DatabaySource{},
		&FlamingoProxiesSource{},
		&FreeProxyListSource{},
		&FreeProxyUpdateSource{},
		&FreeProxyUpdateFilteredSource{},
		&FreeProxyWorldSource{},
		&GeoNodeSource{},
		&GitHubSource{},
		&HideMnSource{},
		&IPRoyalSource{},
		&MyProxySource{},
		&OpenProxyListSource{},
		&ProxyDBSource{},
		&Proxy5050Source{},
		&ProxyListOrgSource{},
		&ProxyListPlusSource{},
		&ProxyNovaSource{},
		&ProxyScrapeSource{},
		&ProxySpaceSource{},
		&SpysOneSource{},
		&SocksProxyNetSource{},
		&SpysMeSource{},
		&UKProxySource{},
	}
}

// FetchAll scrapes all sources concurrently and merges results.
func FetchAll(ctx context.Context, sources []Source) *models.ProxyResult {
	results := make(chan *models.ProxyResult, len(sources))
	var wg sync.WaitGroup
	limit := make(chan struct{}, min(len(sources), allSourcesConcurrency))

	for _, src := range sources {
		wg.Go(func() {
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()
			results <- safeFetch(ctx, src)
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	combined := &models.ProxyResult{}
	seen := map[models.ProxyType]map[string]struct{}{
		models.ProxyTypeHTTP:   {},
		models.ProxyTypeSOCKS4: {},
		models.ProxyTypeSOCKS5: {},
	}
	for r := range results {
		mergeUnique(combined, seen[models.ProxyTypeHTTP], models.ProxyTypeHTTP, r.HTTP)
		mergeUnique(combined, seen[models.ProxyTypeSOCKS4], models.ProxyTypeSOCKS4, r.SOCKS4)
		mergeUnique(combined, seen[models.ProxyTypeSOCKS5], models.ProxyTypeSOCKS5, r.SOCKS5)
	}
	return combined
}

func mergeUnique(result *models.ProxyResult, seen map[string]struct{}, proxyType models.ProxyType, addrs []string) {
	unique := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}
	result.AppendByType(proxyType, unique...)
}
