# WordPress IP Utilities

A lean WordPress utility for IP address validation, CIDR operations, and GDPR-compliant anonymization. Built for real-world plugin development with just the features you actually need.

## Features

* 🎯 **Focused API** - Just 18 essential methods for IP operations
* 🔒 **Privacy Ready** - Built-in anonymization for GDPR compliance
* 🌐 **Full Support** - IPv4 and IPv6 validation and operations
* 📡 **Smart Detection** - Handles proxies, CDNs, and Cloudflare
* 🚫 **Security Features** - CIDR range checking for IP blocking/allowing
* 📦 **Bulk Operations** - Efficient processing of multiple IPs
* 🪶 **Lightweight** - No dependencies, no bloat

## Requirements

* PHP 7.4 or later
* WordPress 5.0 or later

## Installation
```bash
composer require arraypress/wp-utils-ip
```

## Usage

### Getting User IP
```php
use ArrayPress\IPUtils\IP;

// Get current user's IP (handles proxies/CDNs)
$user_ip = IP::get();
// Returns: "203.0.113.42"

// Get anonymized user IP for privacy compliance
$anonymous_ip = IP::get_anonymous();
// Returns: "203.0.113.0"

// Using global function
$user_ip = get_user_ip();
```

### IP Validation
```php
use ArrayPress\IPUtils\IP;

// Validate any IP
if ( IP::is_valid( '192.168.1.100' ) ) {
    // Valid IP address
}

// Check specific versions
$is_ipv4 = IP::is_valid_ipv4( '192.168.1.100' ); // true
$is_ipv6 = IP::is_valid_ipv6( '2001:db8::1' );   // true

// Check if private/reserved
if ( IP::is_private( '192.168.1.1' ) ) {
    // Internal IP address
}
```

### GDPR Anonymization
```php
use ArrayPress\IPUtils\IP;
use ArrayPress\IPUtils\IPs;

// Single IP anonymization
$anonymous = IP::anonymize( '192.168.1.100' );
// Returns: "192.168.1.0"

// Bulk anonymization
$ips = ['192.168.1.100', '10.0.0.50', '8.8.8.8'];
$anonymous_ips = IPs::anonymize( $ips );
// Returns: ['192.168.1.0', '10.0.0.0', '8.8.8.0']

// Using global function
$anonymous = anonymize_ip( '192.168.1.100' );
```

### IP Blocking/Allowing (CIDR)
```php
use ArrayPress\IPUtils\IP;

// Check if IP is in a specific range
if ( IP::is_in_range( '192.168.1.100', '192.168.1.0/24' ) ) {
    // IP is in the subnet
}

// Check against multiple ranges (blocklist/allowlist)
$blocked_ranges = [
    '192.168.1.0/24',  // Internal network
    '10.0.0.0/8',      // Private range
    '203.0.113.5'      // Specific IP
];

if ( IP::is_match( $user_ip, $blocked_ranges ) ) {
    wp_die( 'Access denied from your IP address' );
}

// Validate CIDR format
if ( IP::is_valid_range( '192.168.1.0/24' ) ) {
    // Valid CIDR notation
}
```

### Bulk IP Operations
```php
use ArrayPress\IPUtils\IPs;

$ip_list = [
    '192.168.1.100',
    'invalid-ip',
    '2001:db8::1',
    '10.0.0.50',
    '192.168.1.100'  // Duplicate
];

// Get only valid IPs
$valid = IPs::filter( $ip_list );
// Returns: ['192.168.1.100', '2001:db8::1', '10.0.0.50', '192.168.1.100']

// Remove duplicates
$unique = IPs::remove_duplicates( $ip_list );
// Returns: ['192.168.1.100', '2001:db8::1', '10.0.0.50']

// Get only IPv4 addresses
$ipv4_only = IPs::filter_ipv4( $ip_list );
// Returns: ['192.168.1.100', '10.0.0.50']

// Filter by CIDR range
$office_ips = IPs::filter_by_range( $ip_list, '192.168.1.0/24' );
// Returns: ['192.168.1.100']
```

## Common Use Cases

### GDPR-Compliant Logging
```php
function log_user_activity( $action ) {
    $ip = IP::get_anonymous(); // Already anonymized
    
    $log_entry = [
        'action'    => $action,
        'ip'        => $ip,
        'timestamp' => current_time( 'mysql' )
    ];
    
    // Safe to store - no personal data
    add_option( 'activity_log', $log_entry );
}
```

### Admin Access Control
```php
function restrict_admin_access() {
    $allowed_ips = [
        '192.168.1.0/24',  // Office network
        '10.8.0.0/16',     // VPN range
        '203.0.113.5'      // CEO's home IP
    ];
    
    $user_ip = IP::get();
    
    if ( ! IP::is_match( $user_ip, $allowed_ips ) ) {
        wp_die( 'Admin access restricted to authorized IPs only.' );
    }
}
add_action( 'admin_init', 'restrict_admin_access' );
```

### Rate Limiting
```php
function check_rate_limit() {
    $ip = IP::get();
    
    if ( ! $ip ) {
        return false; // Can't rate limit without IP
    }
    
    $key = 'rate_limit_' . md5( $ip );
    $attempts = get_transient( $key );
    
    if ( $attempts && $attempts > 10 ) {
        wp_die( 'Rate limit exceeded. Please try again later.' );
    }
    
    set_transient( $key, $attempts + 1, HOUR_IN_SECONDS );
}
```

### Geo-Blocking
```php
function block_countries() {
    $blocked_ranges = [
        '1.0.0.0/8',      // Example range
        '2.0.0.0/7',      // Example range
        '5.0.0.0/8'       // Example range
    ];
    
    $user_ip = IP::get();
    
    if ( IP::is_match( $user_ip, $blocked_ranges ) ) {
        wp_die( 'Service not available in your region.' );
    }
}
```

### Clean IP List
```php
function process_ip_whitelist( $raw_ips ) {
    // Validate all IPs
    $valid = IPs::filter( $raw_ips );
    
    // Remove any duplicates
    $unique = IPs::remove_duplicates( $valid );
    
    // Ensure they're public IPs only
    $public = array_filter( $unique, function( $ip ) {
        return ! IP::is_private( $ip );
    });
    
    return $public;
}
```

## API Reference

### IP Class (Single IP Operations)

| Method | Description |
|--------|-------------|
| `get()` | Get current user's IP address |
| `get_anonymous()` | Get anonymized user IP |
| `is_valid( $ip )` | Validate IP address |
| `is_valid_ipv4( $ip )` | Check if valid IPv4 |
| `is_valid_ipv6( $ip )` | Check if valid IPv6 |
| `is_private( $ip )` | Check if private/reserved |
| `is_valid_range( $range )` | Validate CIDR notation |
| `is_in_range( $ip, $range )` | Check if IP in CIDR range |
| `is_match( $ip, $list )` | Check IP against list |
| `anonymize( $ip )` | Anonymize IP for GDPR |

### IPs Class (Multiple IP Operations)

| Method | Description |
|--------|-------------|
| `validate( $ips )` | Validate multiple IPs |
| `filter( $ips )` | Get only valid IPs |
| `anonymize( $ips )` | Bulk anonymize |
| `remove_duplicates( $ips )` | Remove duplicate IPs |
| `filter_ipv4( $ips )` | Get only IPv4 |
| `filter_ipv6( $ips )` | Get only IPv6 |
| `filter_by_range( $ips, $range )` | Filter by CIDR |
| `filter_by_ranges( $ips, $ranges )` | Filter by multiple CIDRs |

### Global Functions
```php
get_user_ip()        // Get current user's IP
anonymize_ip( $ip )  // Anonymize an IP address
```

## Why This Library?

- **Lean & Focused** - Just 18 methods that you'll actually use
- **Real-World Ready** - Built for common WordPress plugin needs
- **Privacy First** - GDPR compliance built in
- **No Bloat** - No academic network calculations or edge cases
- **Clean API** - Separate classes for single vs. multiple operations

## License

GPL-2.0-or-later

## Support

- [Documentation](https://github.com/arraypress/wp-utils-ip)
- [Issue Tracker](https://github.com/arraypress/wp-utils-ip/issues)