
# Proxy List

A curated list of free public proxies, updated frequently to ensure accessibility and usability. These proxies are gathered from various sources and checked for functionality to provide a reliable list.

## Last Updated
**Last Updated**: Saturday, 04 April 2026, 05:52:31 UTC<br>
**Total Scraped Proxies**: 305857<br>
**Total Checked Proxies**: 1384

## Download
```bash
# Scraped Proxies
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/http.txt
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks4.txt
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks5.txt

# Checked Proxies
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.txt
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks4.txt
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks5.txt
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.json
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks4.json
https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks5.json
```

## Technology Stack

- **Language**: Go
- **Proxy Protocols**: HTTP, SOCKS4, SOCKS5
- **Tools Used**: GitHub API (`go-github`), `net/http`, `golang.org/x/net/proxy` for SOCKS support

### Features

1. Automated scraping of proxies from multiple public sources (9 scrapers running concurrently).
2. High-performance validation using a fixed goroutine worker pool with configurable concurrency.
3. IP-based and manual checking modes with fallback chain and retry logic.
4. Transparent proxy detection to filter out non-anonymous proxies.
5. Organized lists of HTTP, SOCKS4, and SOCKS5 proxies (plain text + JSON with metadata).
6. Continuous updates with automated GitHub commits.

## Disclaimer

This repository is intended for educational purposes only. Any misuse of the proxies listed here is strictly discouraged. Always comply with local laws and regulations when using proxies or related tools.


## Contributions

Contributions are welcome! If you have ideas for improvement or additional sources for proxies, feel free to open a pull request or raise an issue.

---

_Made with 🐹💙_
