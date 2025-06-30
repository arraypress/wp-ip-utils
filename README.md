# WordPress IP Utils - Lean IP Address Management

A lightweight WordPress library for IP address operations, validation, and privacy-compliant anonymization. Perfect for analytics, security, and GDPR compliance.

## Features

* 🎯 **Clean API**: WordPress-style snake_case methods with consistent interfaces
* 🔒 **Privacy First**: Built-in anonymization methods for GDPR compliance
* 🌐 **Full IP Support**: IPv4 and IPv6 validation and operations
* 📡 **Smart Detection**: Intelligent user IP detection through proxies and CDNs
* 🎪 **CIDR Operations**: Complete subnet validation and range checking
* 🔢 **Network Math**: IP conversion and network calculations
* 🛡️ **Security Ready**: Private/public IP detection and matching utilities

## Requirements

* PHP 7.4 or later
* WordPress 5.0 or later

## Installation

```bash
composer require arraypress/wp-ip-utils
```

## Basic Usage

### User IP Detection

```php
use ArrayPress\IPUtils\IP;

// Get current user's IP (handles proxies/CDNs)
$user_ip = IP::get();

// Get anonymized user IP for privacy compliance
$anonymous_ip = IP::get_anonymous();
// Returns: "192.168.1.0" instead of "192.168.1.100"
```

### IP Validation

```php
// Validate any IP address
if ( IP::is_valid( '192.168.1.100' ) ) {
	// Valid IP address
}

// Check specific IP versions
$is_ipv4 = IP::is_valid_ipv4( '192.168.1.100' ); // true
$is_ipv6 = IP::is_valid_ipv6( '2001:db8::1' );   // true

// Check if IP is private/public
$is_private = IP::is_private( '192.168.1.1' );   // true
$is_public  = IP::is_public( '8.8.8.8' );         // true
```

### Privacy & Anonymization

```php
// Anonymize IP addresses for GDPR compliance
$anonymous = IP::anonymize( '192.168.1.100' );
// Returns: "192.168.1.0"

$anonymous_ipv6 = IP::anonymize( '2001:db8::1234' );
// Returns: "2001:db8::0"

// Mask IP addresses with asterisks
$masked = IP::mask_last_octet( '192.168.1.100' );
// Returns: "192.168.1.***"

// Check if an IP is already anonymized
if ( IP::is_anonymized( '192.168.1.0' ) ) {
	// IP is already anonymized
}

// Anonymize multiple IPs at once
$ips        = [ '192.168.1.100', '10.0.0.50', '8.8.8.8' ];
$anonymized = IP::anonymize_multiple( $ips );
// Returns: ['192.168.1.0', '10.0.0.0', '8.8.8.0']
```

### CIDR Operations

```php
// Validate CIDR ranges
if ( IP::is_valid_range( '192.168.1.0/24' ) ) {
	// Valid CIDR range
}

// Check if IP is within a range
if ( IP::is_in_range( '192.168.1.100', '192.168.1.0/24' ) ) {
	// IP is in the specified subnet
}

// Check against multiple ranges
$allowed_ranges = [ '192.168.1.0/24', '10.0.0.0/8' ];
if ( IP::is_match( $user_ip, $allowed_ranges ) ) {
	// User IP matches one of the allowed ranges
}
```

### Network Calculations

```php
// Get network address from CIDR
$network = IP::get_network_address( '192.168.1.100/24' );
// Returns: "192.168.1.0"

// Get broadcast address (IPv4 only)
$broadcast = IP::get_broadcast_address( '192.168.1.0/24' );
// Returns: "192.168.1.255"

// Calculate available addresses in range
$count = IP::get_address_count( '192.168.1.0/24' );
// Returns: 254 (256 total - 2 for network and broadcast)
```

### IP Conversion

```php
// Convert IP to decimal
$decimal = IP::to_decimal( '192.168.1.1' );
// Returns: "3232235777"

// Convert back from decimal
$ip   = IP::from_decimal( '3232235777' );        // IPv4
$ipv6 = IP::from_decimal( '42540766411282592875', true ); // IPv6
```

## Common Use Cases

### GDPR Compliance for Analytics

```php
function log_visitor_analytics() {
	$user_ip = IP::get_anonymous(); // Already anonymized

	// Safe to store for analytics
	update_option( 'visitor_ips', $user_ip );
}
```

### Security & Access Control

```php
function check_admin_access() {
	$user_ip      = IP::get();
	$admin_ranges = [
		'192.168.1.0/24',  // Office network
		'10.0.0.0/8',      // VPN range
		'203.0.113.5'      // Specific admin IP
	];

	if ( ! IP::is_match( $user_ip, $admin_ranges ) ) {
		wp_die( 'Access denied from this IP address.' );
	}
}
```

### Rate Limiting by Subnet

```php
function check_rate_limit() {
	$user_ip   = IP::get();
	$subnet_ip = IP::get_network_address( $user_ip . '/24' );

	// Rate limit entire /24 subnet
	$attempts = get_transient( "rate_limit_{$subnet_ip}" );
	if ( $attempts && $attempts > 100 ) {
		wp_die( 'Rate limit exceeded for your network.' );
	}
}
```

### Geolocation Preprocessing

```php
function prepare_ip_for_geolocation() {
	$user_ip = IP::get();

	// Don't geolocate private IPs
	if ( IP::is_private( $user_ip ) ) {
		return null;
	}

	// Use anonymized IP for privacy-compliant geolocation
	return IP::anonymize( $user_ip );
}
```

## Privacy & GDPR Considerations

This library is designed with privacy in mind:

- **Anonymization**: Removes the last octet/group to prevent individual identification
- **No Storage**: User IP detection doesn't store or cache results
- **Configurable**: Easy to implement privacy-first approaches in your applications

### Anonymization Levels

1. **Full Anonymization**: `IP::anonymize()` - Zeros out last segment
2. **Visual Masking**: `IP::mask_last_octet()` - Replaces with asterisks
3. **Subnet-level**: Use with CIDR operations for broader anonymization

## IPv6 Support

Full IPv6 support including:
- Validation and type detection
- Anonymization (zeros last group)
- CIDR range operations
- Network calculations
- Conversion utilities

## Error Handling

All methods return `null`, `false`, or empty arrays for invalid inputs rather than throwing exceptions, making them safe for direct use in conditionals.

## Requirements

- PHP 7.4+
- WordPress 5.0+

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL-2.0-or-later License.

## Support

- [Documentation](https://github.com/arraypress/wp-ip-utils)
- [Issue Tracker](https://github.com/arraypress/wp-ip-utils/issues)