
# Proxy List

A curated list of free public proxies, updated frequently to ensure accessibility and usability. These proxies are gathered from various sources and checked for functionality to provide a reliable list.

## Last Updated
<!-- generated:stats:start -->
**Last Updated**: Saturday, 04 April 2026, 13:43:38 UTC<br>
**Total Scraped Proxies**: 304792<br>
**Total Checked Proxies**: 1259
<!-- generated:stats:end -->

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

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `IP_CHECKER` | `ipify` | IP-check endpoint to use. Supported values: `ipify`, `httpbin`, `httpbun`, `icanhazip`, `ifconfig`, `manual`. |
| `MAX_WORKERS` | `100` | Maximum concurrent proxy checks. Minimum: `1`. |
| `CHECK_TIMEOUT_CONNECT` | `5s` | Connection timeout for each proxy check. Accepts Go durations like `5s` / `750ms` and legacy numeric seconds like `5`. |
| `CHECK_TIMEOUT_READ` | `10s` | Read timeout for each proxy check. Accepts Go durations like `10s` / `1500ms` and legacy numeric seconds like `10`. |
| `MAX_RETRIES` | `1` | Additional retries after the first failed attempt. Minimum: `0`. |
| `SLEEP_SECONDS` | `7200` | Delay between cycles when `RUN_ONCE=false`. |
| `RUN_ONCE` | `false` | Run a single scrape/check/publish cycle and exit. |
| `GITHUB_TOKEN` | _(empty)_ | Token used to publish refreshed lists back to the target repository. |
| `GITHUB_REPO` | _(empty)_ | Target repository in `owner/repo` format. |

## Checking modes

- `manual` mode verifies that a known page loads through the proxy instead of comparing returned public IPs.
- All other modes query public IP-check endpoints and reject transparent proxies when the returned IP matches the machine's detected real IP.
- If real-IP detection fails temporarily, the checker now retries on later runs instead of disabling transparency filtering for the entire process.

## Notes

- Public proxy sources are noisy by nature; some entries are invalid, stale, duplicated, or rate-limited at the source.
- Only the managed proxy list files are updated through the GitHub publisher; unrelated repository files are preserved.

## Disclaimer

This repository is intended for educational purposes only. Any misuse of the proxies listed here is strictly discouraged. Always comply with local laws and regulations when using proxies or related tools.


## Contributions

Contributions are welcome! If you have ideas for improvement or additional sources for proxies, feel free to open a pull request or raise an issue.

---

_Made with 🐹💙_
