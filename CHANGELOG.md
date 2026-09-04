# Changelog

## 1.1.2

### Fixed

- **`IP::is_tor()` believes Cloudflare only through Cloudflare.** It read
  the CF-IPCountry header from anyone, so a visitor reaching the origin
  directly could send `T1` and trip, or dodge, a Tor rule. It now applies
  the same trusted-proxy rule as `IP::get()`: the header is read only when
  REMOTE_ADDR is a trusted proxy.

## 1.1.1

### Added

- **`IP::get( bool $allow_private = false )`.** Returns private,
  loopback and reserved addresses instead of null — for audit logs and
  intranet deployments, where "logged in from 192.168.1.50" is the data
  you actually want. The trusted-proxy rule is unchanged: this loosens
  which *addresses* are acceptable, never which *sources* are believed.

  Consumers that previously reimplemented a permissive header cascade
  inline should call `IP::get( true )` instead, so the trust gate is
  inherited rather than bypassed.

  On an intranet the client is itself inside the default trusted range
  (RFC 1918), so the right-to-left walk would skip the real visitor as
  infrastructure. In permissive mode only, the client-most entry is used
  as a fallback. That value is advisory for an audit log, not a security
  boundary — set `ARRAYPRESS_TRUSTED_PROXIES` to your real proxy
  addresses if you need it to be authoritative.

## 1.1.0

### Security

**`IP::get()` no longer trusts forwarding headers from untrusted sources.**

Previously the header list was walked in priority order and the first
valid public address won, with no check on where the request came from.
`X-Forwarded-For`, `X-Real-IP`, `Client-IP` and `CF-Connecting-IP` are
ordinary request headers that anyone can send, so any client able to
reach the origin directly — a leaked origin address, a DNS record that
bypasses the CDN, an exposed health-check port — could declare whatever
IP it liked. Everything keyed on the client address then belonged to the
caller: rate limits, blocklists, fraud scoring, audit trails, geo rules.

Forwarding headers are now read only when `REMOTE_ADDR` is itself in
`IP::trusted_proxies()`. Otherwise `REMOTE_ADDR` is used and the headers
are ignored.

`X-Forwarded-For` is also now read from the **right-hand end**, skipping
known proxies. The leftmost entry is the one part of that header a
client fully controls, and reading it was the bug in miniature.

**Configuration.** Defaults trust Cloudflare's published ranges plus
loopback and RFC 1918, which covers the common deployments. Override
with either:

```php
define( 'ARRAYPRESS_TRUSTED_PROXIES', '203.0.113.5,198.51.100.0/24' );

add_filter( 'arraypress_trusted_proxies', fn( array $r ) => [ '203.0.113.5' ] );
```

Set it empty when nothing proxies your site — then no forwarding header
is ever believed, which is the safest configuration.

**Upgrade note.** If you sit behind a CDN or load balancer that is
neither Cloudflare nor on a private address, add its ranges or visitors
will appear as the proxy. This fails closed, which is the correct
direction, but it is still a behaviour change.

### Fixed

- **Fatal error on mixed-family lists.** `is_in_range()` dispatched on
  the address family without checking the range's, so an IPv4 address
  tested against an IPv6 range reached the IPv4 comparison with a
  128-bit prefix and threw `ArithmeticError: Bit shift by negative
  number`. Any `is_match()` call against a list holding both IPv4 and
  IPv6 entries crashed. Mismatched families are now a miss.

- **Deprecation in IPv6 range matching.** `chr( 0xFF << n )` produces a
  value above 255, which PHP 8.1 deprecated and a future version will
  reject. Now masked to a byte. Prefix widths are also clamped to
  0–128, and unparseable input returns false instead of operating on
  `false`.

### Added

- `IP::trusted_proxies()` — the configured proxy ranges.
- `IP::is_trusted_proxy()` — whether an address is one of them.
- `tests/` — plain-PHP suites, no PHPUnit. `php tests/client-ip.php`.
