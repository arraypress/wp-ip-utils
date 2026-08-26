# WordPress IP Utilities

Get the visitor's real IP, and check it against the rules you care about.

## What it does

`$_SERVER['REMOTE_ADDR']` is the proxy's address when there is a proxy, and
`HTTP_X_FORWARDED_FOR` is attacker-controlled unless you know which proxy you
trust. Getting this wrong means either everyone shares one IP, or anyone can
claim any IP they like.

This reads the forwarding headers only when the connecting address is a proxy
you have declared, and falls back to `REMOTE_ADDR` otherwise. Then it answers
the follow-ups: is this in that CIDR range, does it match that wildcard, and
what does it look like with the last octet dropped for GDPR.

## Features

- Read the visitor's IP, honouring forwarding headers only from trusted proxies
- Validate IPv4 and IPv6, and tell private ranges from public ones
- Test membership of a CIDR range, or a list of ranges
- Match wildcard patterns like `192.168.1.*` for block lists
- Anonymise for GDPR by masking the last octet, or the last 80 bits of IPv6
- Recognise Cloudflare, and read its ray id
- Validate and clean a user-entered list of IPs and patterns

## Installation

```bash
composer require arraypress/wp-ip-utils
```

## Quick start

```php
use ArrayPress\IPUtils\IP;

// Behind Cloudflare or a load balancer, declare it first.
IP::trusted_proxies( [ '173.245.48.0/20', '103.21.244.0/22' ] );

$ip = IP::get();

// Block by CIDR or wildcard, from a setting.
if ( IP::is_match( $ip, $blocked_patterns ) ) {
    wp_die( 'Access denied' );
}

// Store it without storing all of it.
$for_logs = IP::anonymize( $ip );   // 203.0.113.0
```

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later

## License

GPL-2.0-or-later
