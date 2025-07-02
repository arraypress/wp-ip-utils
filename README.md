# WordPress IP Utils - Lean IP Address Management

A lightweight PHP library for IP address operations, validation, and privacy-compliant anonymization. Designed with clean APIs and efficient bulk operations.

## Features

* 🎯 **Clean API**: Separate classes for single (`IP`) and multiple (`IPs`) operations
* 🔒 **Privacy First**: Built-in anonymization methods for GDPR compliance
* 🌐 **Full IP Support**: IPv4 and IPv6 validation and operations
* 📡 **Smart Detection**: Intelligent user IP detection through proxies and CDNs
* 🎪 **CIDR Operations**: Complete subnet validation and range checking
* 🔢 **Network Math**: IP conversion and network calculations
* 🛡️ **Security Ready**: Private/public IP detection and matching utilities
* 📊 **Bulk Operations**: Efficient processing of multiple IP addresses
* ⚡ **Lean Design**: No external dependencies, optimized for performance

## Requirements

* PHP 7.4 or later

## Installation

```bash
composer require arraypress/wp-ip-utils
```

## Basic Usage

### Single IP Operations (`IP` class)

```php
use ArrayPress\IPUtils\IP;

// Get current user's IP (handles proxies/CDNs)
$user_ip = IP::get();

// Get anonymized user IP for privacy compliance
$anonymous_ip = IP::get_anonymous();
// Returns: "192.168.1.0" instead of "192.168.1.100"

// Validation
if ( IP::is_valid( '192.168.1.100' ) ) {
	// Valid IP address
}

// Check specific IP versions
$is_ipv4 = IP::is_valid_ipv4( '192.168.1.100' ); // true
$is_ipv6 = IP::is_valid_ipv6( '2001:db8::1' );   // true

// Check if IP is private/public
$is_private = IP::is_private( '192.168.1.1' );   // true
$is_public  = IP::is_public( '8.8.8.8' );        // true
```

### Multiple IP Operations (`IPs` class)

```php
use ArrayPress\IPUtils\IPs;

$ips = [
	'192.168.1.100',
	'invalid-ip',
	'2001:db8::1',
	'10.0.0.50'
];

// Bulk validation
$valid_ips          = IPs::filter( $ips ); // Get only valid IPs
$invalid_ips        = IPs::invalid( $ips ); // Get only invalid IPs
$validation_results = IPs::validate( $ips ); // Get all results

// Bulk anonymization
$anonymous_ips = IPs::anonymize( $ips );
$masked_ips    = IPs::mask( $ips );

// Extract from text
$text      = "Connect to servers 192.168.1.1 and 2001:db8::1 for access";
$extracted = IPs::extract( $text );
// Returns: ["192.168.1.1", "2001:db8::1"]
```

## Advanced Features

### Privacy & Anonymization

```php
// Single IP operations
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

// Bulk operations
$anonymous_ips = IPs::anonymize( $ips );
$masked_ips    = IPs::mask( $ips );
```

### IP Type & Privacy Filtering

```php
// Filter by IP type
$ipv4_only = IPs::filter_ipv4( $ips );      // Get only IPv4 addresses
$ipv6_only = IPs::filter_ipv6( $ips );      // Get only IPv6 addresses

// Filter by privacy status
$private_ips = IPs::filter_private( $ips );  // Get only private IPs
$public_ips  = IPs::filter_public( $ips );    // Get only public IPs

// Generic filtering
$ipv4_ips    = IPs::filter_by_type( $ips, 'ipv4' );
$private_ips = IPs::filter_by_privacy( $ips, 'private' );
```

### CIDR Operations

```php
// Single IP CIDR operations
if ( IP::is_valid_range( '192.168.1.0/24' ) ) {
	// Valid CIDR range
}

if ( IP::is_in_range( '192.168.1.100', '192.168.1.0/24' ) ) {
	// IP is in the specified subnet
}

// Check against multiple ranges
$allowed_ranges = [ '192.168.1.0/24', '10.0.0.0/8' ];
if ( IP::is_match( $user_ip, $allowed_ranges ) ) {
	// User IP matches one of the allowed ranges
}

// Bulk CIDR operations
$office_range = '192.168.1.0/24';
$office_ips   = IPs::filter_by_range( $ips, $office_range );

// Filter by multiple ranges
$internal_ranges = [ '192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12' ];
$internal_ips    = IPs::filter_by_ranges( $ips, $internal_ranges );

// Group IPs by ranges
$ranges  = [
	'office' => '192.168.1.0/24',
	'vpn'    => '10.0.0.0/8',
	'dmz'    => '172.16.0.0/16'
];
$grouped = IPs::group_by_ranges( $ips, $ranges );
// Returns: ['office' => [...], 'vpn' => [...], 'dmz' => [...], 'other' => [...]]
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

### IP Conversion & Analysis

```php
// Convert IP to decimal
$decimal = IP::to_decimal( '192.168.1.1' );
// Returns: "3232235777"

// Convert back from decimal
$ip   = IP::from_decimal( '3232235777' );        // IPv4
$ipv6 = IP::from_decimal( '42540766411282592875', true ); // IPv6

// Bulk conversion
$decimals = IPs::to_decimal( $ips );
// Returns: ['192.168.1.1' => '3232235777', ...]

// Check anonymization status
$anonymized_status = IPs::check_anonymized( $ips );
// Returns: ['192.168.1.0' => true, '192.168.1.100' => false, ...]
```

### IP Statistics & Analysis

```php
// Get comprehensive statistics
$stats = IPs::get_statistics( $ips );
/*
Returns:
[
    'total' => 100,
    'valid' => 95,
    'invalid' => 5,
    'valid_percent' => 95.0,
    'ipv4_count' => 80,
    'ipv6_count' => 15,
    'ipv4_percent' => 84.21,
    'ipv6_percent' => 15.79,
    'private_count' => 60,
    'public_count' => 35,
    'private_percent' => 63.16,
    'public_percent' => 36.84,
    'anonymized_count' => 10,
    'unique_count' => 92
]
*/
```

### Duplicate Management

```php
$ips_with_duplicates = [
	'192.168.1.1',
	'192.168.1.1',    // Duplicate
	'2001:db8::1',
	'invalid-ip'
];

// Remove duplicates
$unique_ips = IPs::remove_duplicates( $ips_with_duplicates );
// Returns: ['192.168.1.1', '2001:db8::1']
```

## Use Cases

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

### IP List Cleaning

```php
function clean_ip_list( array $ips ): array {
	// Remove invalid IPs, optionally remove private IPs, remove duplicates
	return IPs::clean( $ips, $remove_private = false, $remove_duplicates = true );
}

function get_public_ips_only( array $ips ): array {
	// Get only valid, public IP addresses
	$valid = IPs::filter( $ips );

	return IPs::filter_public( $valid );
}
```

### Network Analysis

```php
function analyze_server_logs( array $log_ips ): array {
	$stats = IPs::get_statistics( $log_ips );

	return [
		'total_requests'           => $stats['total'],
		'unique_visitors'          => $stats['unique_count'],
		'internal_traffic_percent' => $stats['private_percent'],
		'ipv6_adoption_percent'    => $stats['ipv6_percent']
	];
}
```

### Geolocation Preprocessing

```php
function prepare_ips_for_geolocation( array $ips ): array {
	// Filter out private IPs and anonymize for privacy compliance
	$public_ips = IPs::filter_public( $ips );

	return IPs::anonymize( $public_ips );
}
```

## Privacy & GDPR Considerations

This library is designed with privacy in mind:

### Anonymization Methods

```php
// Full anonymization - safe for storage
$anonymous = IP::anonymize( '192.168.1.100' );
// Returns: "192.168.1.0"

// Visual masking - safe for display
$masked = IP::mask_last_octet( '192.168.1.100' );
// Returns: "192.168.1.***"

// Check if already anonymized
$is_anon = IP::is_anonymized( '192.168.1.0' ); // true
```

### Bulk Privacy Operations

```php
// Anonymize multiple IPs for analytics
$anonymous_ips = IPs::anonymize( $user_ips );

// Clean and prepare IPs for storage
$clean_ips = IPs::clean( $raw_ips, true ); // Remove private IPs too
```

## API Reference

### IP Class (Single Operations)

**Validation:**
- `is_valid( string $ip ): bool`
- `is_valid_ipv4( string $ip ): bool`
- `is_valid_ipv6( string $ip ): bool`
- `is_private( string $ip ): bool`
- `is_public( string $ip ): bool`

**User IP Detection:**
- `get(): ?string`                          # Get current user's IP
- `get_anonymous(): ?string`                # Get anonymized user IP

**Privacy:**
- `anonymize( string $ip ): ?string`
- `mask_last_octet( string $ip ): ?string`
- `is_anonymized( string $ip ): bool`

**CIDR Operations:**
- `is_valid_range( string $range ): bool`
- `is_in_range( string $ip, string $range ): bool`
- `is_match( string $ip, array $ip_list ): bool`

**Network Calculations:**
- `get_network_address( string $cidr ): string`
- `get_broadcast_address( string $cidr ): string`
- `get_address_count( string $cidr ): int`

**Conversion:**
- `to_decimal( string $ip ): string`
- `from_decimal( string $decimal, bool $is_ipv6 = false ): string`

### IPs Class (Bulk Operations)

**Validation & Filtering:**
- `validate( array $ips ): array`             # Get validation results for all
- `filter( array $ips ): array`               # Return only valid IPs
- `invalid( array $ips ): array`              # Return only invalid IPs

**Text Processing:**
- `extract(string $text): array`            # Extract IPs from text
- `remove_duplicates( array $ips ): array`

**Privacy:**
- `anonymize( array $ips ): array`            # Anonymize multiple IPs
- `mask( array $ips ): array`                 # Mask multiple IPs

**Type & Privacy Filtering:**
- `filter_ipv4( array $ips ): array`
- `filter_ipv6( array $ips ): array`
- `filter_private( array $ips ): array`
- `filter_public( array $ips ): array`
- `filter_by_type( array $ips, string $type ): array`
- `filter_by_privacy( array $ips, string $type ): array`

**CIDR Operations:**
- `filter_by_range( array $ips, string $range, bool $include = true ): array`
- `filter_by_ranges( array $ips, array $ranges, bool $include = true ): array`
- `group_by_ranges( array $ips, array $ranges ): array`

**Analysis:**
- `get_statistics( array $ips ): array`
- `to_decimal( array $ips ): array`
- `check_anonymized( array $ips ): array`

**Cleaning:**
- `clean( array $ips, bool $remove_private = false, bool $remove_duplicates = true ): array`

## IPv6 Support

Full IPv6 support including:
- Validation and type detection
- Anonymization (zeros last group)
- CIDR range operations
- Network calculations
- Conversion utilities

## Error Handling

All methods return `null`, `false`, or empty arrays for invalid inputs rather than throwing exceptions, making them safe for direct use in conditionals.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL-2.0-or-later License.

## Support

- [Documentation](https://github.com/arraypress/wp-ip-utils)
- [Issue Tracker](https://github.com/arraypress/wp-ip-utils/issues)