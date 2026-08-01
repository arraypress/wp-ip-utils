# Tests

Plain PHP, no PHPUnit — run them directly:

```bash
php tests/client-ip.php
php tests/mixed-family.php
```

Both exit non-zero on failure, so they drop straight into CI.

- **client-ip.php** — proves forwarding headers are ignored unless the
  connection came from a trusted proxy, and that `X-Forwarded-For` is
  read from the right-hand end.
- **mixed-family.php** — regression cover for the mixed IPv4/IPv6 list
  crash fixed in 1.1.0.
