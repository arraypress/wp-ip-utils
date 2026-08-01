<?php
/**
 * IP Utility Class
 *
 * Provides utility functions for working with IP addresses,
 * including validation, CIDR operations, and user IP detection.
 *
 * @package ArrayPress\IPUtils
 * @since   1.0.0
 * @author  ArrayPress
 * @license GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace ArrayPress\IPUtils;

/**
 * IP Class
 *
 * Core operations for working with IP addresses.
 */
class IP {

	/**
	 * Forwarding headers, in order of priority.
	 *
	 * These are ONLY consulted when the connection itself arrived from a
	 * trusted proxy — see {@see IP::get()}. They are ordinary request
	 * headers, so anyone can send them.
	 */
	private const FORWARDED_HEADERS = [
		'HTTP_CF_CONNECTING_IP',    // Cloudflare
		'HTTP_X_REAL_IP',           // Nginx proxy
		'HTTP_X_FORWARDED_FOR',     // Standard proxy chain
		'HTTP_CLIENT_IP',           // Legacy proxy
	];

	/**
	 * Proxy ranges trusted by default.
	 *
	 * Cloudflare's published ranges plus loopback and RFC 1918, which
	 * covers the usual deployments: behind Cloudflare, or behind nginx /
	 * Caddy / HAProxy on the same host or private network.
	 *
	 * Override with the ARRAYPRESS_TRUSTED_PROXIES constant or the
	 * 'arraypress_trusted_proxies' filter. Cloudflare's list changes —
	 * refresh from https://www.cloudflare.com/ips/.
	 */
	private const DEFAULT_TRUSTED_PROXIES = [
		// Loopback and private networks.
		'127.0.0.0/8',
		'::1/128',
		'10.0.0.0/8',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'fd00::/8',
		// Cloudflare IPv4.
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		// Cloudflare IPv6.
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	];

	/**
	 * Cloudflare country header name.
	 */
	private const CF_COUNTRY_HEADER = 'HTTP_CF_IPCOUNTRY';

	/**
	 * Cloudflare header for request ray ID.
	 */
	private const CF_RAY_HEADER = 'HTTP_CF_RAY';

	/**
	 * Get the current user's IP address.
	 *
	 * Forwarding headers (X-Forwarded-For, CF-Connecting-IP, and friends)
	 * are ordinary request headers that anyone can send. They are only
	 * meaningful when the request actually arrived through a proxy you
	 * put there, so they are consulted only when REMOTE_ADDR is itself in
	 * {@see IP::trusted_proxies()}. Otherwise REMOTE_ADDR is used and the
	 * headers are ignored, whatever they claim.
	 *
	 * Without that check, anyone able to reach the origin directly — a
	 * leaked origin address, a DNS record that bypasses the CDN, an open
	 * health-check port — can declare any IP they like, and every
	 * IP-keyed decision becomes theirs to control.
	 *
	 * @return string|null The user's IP address, or null if not found/invalid.
	 * @since  1.1.0 Forwarding headers now require a trusted proxy.
	 */
	public static function get(): ?string {
		$remote = trim( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		$remote = self::is_valid( $remote ) ? $remote : null;

		if ( null !== $remote && self::is_trusted_proxy( $remote ) ) {
			foreach ( self::FORWARDED_HEADERS as $header ) {
				if ( empty( $_SERVER[ $header ] ) ) {
					continue;
				}

				$found = self::from_forwarded( (string) $_SERVER[ $header ] );

				if ( null !== $found ) {
					return $found;
				}
			}
		}

		return ( null !== $remote && ! self::is_private( $remote ) ) ? $remote : null;
	}

	/**
	 * Extract the client address from a forwarding header value.
	 *
	 * X-Forwarded-For grows left to right as it passes through proxies:
	 * "client, proxy1, proxy2". Entries appended by trusted proxies can
	 * be believed; everything to the left of those came from whoever
	 * called first, and a client can pre-seed the header with invented
	 * hops. So the list is walked from the RIGHT, skipping our own
	 * proxies, and the first remaining address wins.
	 *
	 * Taking the leftmost entry — the common implementation — takes the
	 * one value in the header an attacker fully controls.
	 *
	 * @param string $value Raw header value.
	 *
	 * @return string|null Client address, or null if none usable.
	 * @since  1.1.0
	 */
	private static function from_forwarded( string $value ): ?string {
		$parts = array_reverse( array_map( 'trim', explode( ',', $value ) ) );

		foreach ( $parts as $candidate ) {
			$candidate = self::strip_port( $candidate );

			if ( ! self::is_valid( $candidate ) ) {
				continue;
			}

			// Skip our own infrastructure to reach the real client.
			if ( self::is_trusted_proxy( $candidate ) ) {
				continue;
			}

			return self::is_private( $candidate ) ? null : $candidate;
		}

		return null;
	}

	/**
	 * Remove a trailing port, handling bracketed IPv6.
	 *
	 * @param string $value Address, possibly with a port.
	 *
	 * @return string
	 * @since  1.1.0
	 */
	private static function strip_port( string $value ): string {
		$value = trim( $value );

		if ( str_starts_with( $value, '[' ) ) {
			$close = strpos( $value, ']' );

			return $close === false ? $value : substr( $value, 1, $close - 1 );
		}

		// A bare IPv6 address has several colons and no port, so only
		// strip when there is exactly one.
		if ( substr_count( $value, ':' ) === 1 ) {
			return explode( ':', $value, 2 )[0];
		}

		return $value;
	}

	/**
	 * Whether an address is one of our own proxies.
	 *
	 * @param string $ip Address to check.
	 *
	 * @return bool
	 * @since  1.1.0
	 */
	public static function is_trusted_proxy( string $ip ): bool {
		$proxies = self::trusted_proxies();

		return ! empty( $proxies ) && self::is_match( $ip, $proxies );
	}

	/**
	 * The proxy ranges whose forwarding headers are believed.
	 *
	 * Configure with either:
	 *
	 *   define( 'ARRAYPRESS_TRUSTED_PROXIES', '203.0.113.5,198.51.100.0/24' );
	 *
	 *   add_filter( 'arraypress_trusted_proxies', function ( array $ranges ) {
	 *       return [ '203.0.113.5' ];
	 *   } );
	 *
	 * Set it to an empty list when the application is reached directly —
	 * then no forwarding header is ever believed, which is the safest
	 * configuration and the correct one without a proxy.
	 *
	 * @return array List of IPs, CIDR ranges, or wildcard patterns.
	 * @since  1.1.0
	 */
	public static function trusted_proxies(): array {
		$proxies = self::DEFAULT_TRUSTED_PROXIES;

		if ( defined( 'ARRAYPRESS_TRUSTED_PROXIES' ) ) {
			$configured = constant( 'ARRAYPRESS_TRUSTED_PROXIES' );
			$proxies    = is_array( $configured )
				? $configured
				: array_filter( array_map( 'trim', explode( ',', (string) $configured ) ) );
		}

		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'arraypress_trusted_proxies', $proxies );

			if ( is_array( $filtered ) ) {
				$proxies = $filtered;
			}
		}

		return $proxies;
	}

	/**
	 * Get an anonymized version of the user's IP address.
	 *
	 * @return string|null Anonymized IP address or null if no valid IP found.
	 */
	public static function get_anonymous(): ?string {
		$ip = self::get();

		return $ip ? self::anonymize( $ip ) : null;
	}

	/**
	 * Validate an IP address (IPv4 or IPv6).
	 *
	 * @param string $ip The IP address to validate.
	 *
	 * @return bool True if the IP address is valid.
	 */
	public static function is_valid( string $ip ): bool {
		return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
	}

	/**
	 * Validate an IPv4 address.
	 *
	 * @param string $ip The IP address to validate.
	 *
	 * @return bool True if valid IPv4.
	 */
	public static function is_valid_ipv4( string $ip ): bool {
		return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== false;
	}

	/**
	 * Validate an IPv6 address.
	 *
	 * @param string $ip The IP address to validate.
	 *
	 * @return bool True if valid IPv6.
	 */
	public static function is_valid_ipv6( string $ip ): bool {
		return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== false;
	}

	/**
	 * Check if an IP address is private/reserved.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool True if the IP is private/reserved.
	 */
	public static function is_private( string $ip ): bool {
		return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false;
	}

	/**
	 * Check if an IP address or range is in valid CIDR format.
	 *
	 * @param string $range The IP range to validate.
	 *
	 * @return bool True if valid CIDR format.
	 */
	public static function is_valid_range( string $range ): bool {
		if ( ! str_contains( $range, '/' ) ) {
			return false;
		}

		[ $ip, $subnet ] = explode( '/', $range, 2 );
		if ( ! is_numeric( $subnet ) ) {
			return false;
		}

		$subnet = (int) $subnet;
		if ( self::is_valid_ipv4( $ip ) ) {
			return $subnet >= 0 && $subnet <= 32;
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			return $subnet >= 0 && $subnet <= 128;
		}

		return false;
	}

	/**
	 * Check if an IP address is within a specified CIDR range.
	 *
	 * @param string $ip    The IP address to check.
	 * @param string $range The IP range in CIDR format.
	 *
	 * @return bool True if IP is in range.
	 */
	public static function is_in_range( string $ip, string $range ): bool {
		if ( ! self::is_valid( $ip ) || ! self::is_valid_range( $range ) ) {
			return false;
		}

		[ $subnet, $bits ] = explode( '/', $range );
		$bits = (int) $bits;

		// Both sides must be the same family. Dispatching on the address
		// alone sends an IPv4 address into the IPv4 comparison with an
		// IPv6 prefix length, and "32 - 128" is a fatal ArithmeticError
		// rather than a false. Mixed lists are perfectly ordinary, so
		// this has to be a miss, not a crash.
		if ( self::is_valid_ipv4( $ip ) && self::is_valid_ipv4( $subnet ) ) {
			return self::is_ipv4_in_range( $ip, $subnet, $bits );
		}

		if ( self::is_valid_ipv6( $ip ) && self::is_valid_ipv6( $subnet ) ) {
			return self::is_ipv6_in_range( $ip, $subnet, $bits );
		}

		return false;
	}

	/**
	 * Check if an IP address matches any in a list of IPs, ranges, or wildcards.
	 *
	 * @param string $ip      The IP address to check.
	 * @param array  $ip_list List of IPs, CIDR ranges, or wildcard patterns.
	 *
	 * @return bool Whether the IP address matches any in the list.
	 */
	public static function is_match( string $ip, array $ip_list ): bool {
		$ip = trim( $ip );
		if ( empty( $ip ) || ! self::is_valid( $ip ) ) {
			return false;
		}

		foreach ( $ip_list as $pattern ) {
			$pattern = trim( $pattern );

			// Exact match.
			if ( $pattern === $ip ) {
				return true;
			}

			// CIDR range match.
			if ( str_contains( $pattern, '/' ) && self::is_valid_range( $pattern ) ) {
				if ( self::is_in_range( $ip, $pattern ) ) {
					return true;
				}
			}

			// Wildcard match.
			if ( str_contains( $pattern, '*' ) && self::matches_wildcard( $ip, $pattern ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Anonymize an IP address by zeroing out the last octet (IPv4) or the last group (IPv6).
	 *
	 * @param string $ip The IP address to anonymize.
	 *
	 * @return string|null The anonymized IP address, or null if invalid.
	 */
	public static function anonymize( string $ip ): ?string {
		if ( ! self::is_valid( $ip ) ) {
			return null;
		}

		if ( self::is_valid_ipv4( $ip ) ) {
			return preg_replace( '/\.\d+$/', '.0', $ip );
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			// Handle special case of all-zeros IPv6
			if ( $ip === '::' ) {
				return '::'; // Already all zeros, no need to change
			}

			// For all other IPv6 addresses, replace the last group with 0
			return preg_replace( '/:[^:]*$/', ':0', $ip );
		}

		return null;
	}

	// ========================================
	// Country Detection
	// ========================================

	/**
	 * Get country code from Cloudflare header.
	 *
	 * @return string|null Two-letter country code or null if unavailable.
	 */
	public static function get_country(): ?string {
		if ( empty( $_SERVER[ self::CF_COUNTRY_HEADER ] ) ) {
			return null;
		}

		$country = strtoupper( substr( $_SERVER[ self::CF_COUNTRY_HEADER ], 0, 2 ) );

		return ( preg_match( '/^[A-Z]{2}$/', $country ) && $country !== 'XX' )
			? $country
			: null;
	}

	/**
	 * Check if request is from Tor exit node (via Cloudflare).
	 *
	 * @return bool True if Tor exit node.
	 */
	public static function is_tor(): bool {
		return ( $_SERVER[ self::CF_COUNTRY_HEADER ] ?? '' ) === 'T1';
	}

	// ========================================
	// Request Information
	// ========================================

	/**
	 * Get Cloudflare ray ID for request tracing.
	 *
	 * @return string|null Ray ID or null if not behind Cloudflare.
	 */
	public static function get_ray_id(): ?string {
		return $_SERVER[ self::CF_RAY_HEADER ] ?? null;
	}

	// ========================================
	// Private Helper Methods
	// ========================================

	/**
	 * Checks if an IPv4 address is within a specified range.
	 *
	 * @param string $ip     The IPv4 address to check.
	 * @param string $subnet The subnet of the range.
	 * @param int    $bits   The number of network bits.
	 *
	 * @return bool True if IPv4 is in range.
	 */
	private static function is_ipv4_in_range( string $ip, string $subnet, int $bits ): bool {
		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		$mask        = - 1 << ( 32 - $bits );
		$subnet_long &= $mask;

		return ( $ip_long & $mask ) === $subnet_long;
	}

	/**
	 * Checks if an IPv6 address is within a specified range.
	 *
	 * @param string $ip     The IPv6 address to check.
	 * @param string $subnet The subnet of the range.
	 * @param int    $bits   The number of network bits.
	 *
	 * @return bool True if IPv6 is in range.
	 */
	private static function is_ipv6_in_range( string $ip, string $subnet, int $bits ): bool {
		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );

		if ( $ip_bin === false || $subnet_bin === false ) {
			return false;
		}

		$bits = max( 0, min( 128, $bits ) );

		// Create mask.
		$mask      = str_repeat( "\xFF", $bits >> 3 );
		$remainder = $bits & 7;
		if ( $remainder ) {
			// Mask to a byte: "0xFF << n" produces a value above 255,
			// which chr() has deprecated and which will become an error.
			$mask .= chr( ( 0xFF << ( 8 - $remainder ) ) & 0xFF );
		}
		$mask = str_pad( $mask, 16, "\x00" );

		return ( ( $ip_bin & $mask ) === ( $subnet_bin & $mask ) );
	}

	/**
	 * Check if an IP matches a wildcard pattern.
	 *
	 * @param string $ip      The IP address to check.
	 * @param string $pattern Wildcard pattern (e.g., 192.168.1.*).
	 *
	 * @return bool True if IP matches the pattern.
	 */
	public static function matches_wildcard( string $ip, string $pattern ): bool {
		if ( ! self::is_valid( $ip ) || ! str_contains( $pattern, '*' ) ) {
			return false;
		}

		$regex = '/^' . str_replace( [ '.', '*' ], [ '\\.', '\\d+' ], $pattern ) . '$/';

		return preg_match( $regex, $ip ) === 1;
	}

	/**
	 * Check if a string is a valid IP pattern.
	 *
	 * Valid patterns:
	 * - Single IP: 192.168.1.1
	 * - CIDR range: 192.168.1.0/24
	 *
	 * @param string $pattern The pattern to validate.
	 *
	 * @return bool True if valid pattern.
	 */
	public static function is_valid_pattern( string $pattern ): bool {
		$pattern = trim( $pattern );

		if ( empty( $pattern ) ) {
			return false;
		}

		// Valid IP.
		if ( self::is_valid( $pattern ) ) {
			return true;
		}

		// Valid CIDR range.
		if ( self::is_valid_range( $pattern ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Filter a list to only valid IP patterns.
	 *
	 * @param array $patterns List of patterns.
	 *
	 * @return array Valid patterns only.
	 */
	public static function filter_valid_patterns( array $patterns ): array {
		return array_values( array_filter( $patterns, [ self::class, 'is_valid_pattern' ] ) );
	}

	/**
	 * Sanitize and filter a list of IP patterns.
	 *
	 * Takes raw input (string or array) and returns a clean array of valid patterns.
	 *
	 * @param string|array $input     Raw input - newline-separated string or array.
	 * @param bool         $as_string Return as newline-separated string instead of array.
	 *
	 * @return array|string Sanitized valid patterns.
	 */
	public static function sanitize_pattern_list( $input, bool $as_string = false ) {
		// Convert string to array.
		if ( is_string( $input ) ) {
			$patterns = explode( "\n", $input );
		} else {
			$patterns = (array) $input;
		}

		// Clean up each pattern.
		$patterns = array_map( 'trim', $patterns );
		$patterns = array_filter( $patterns );

		// WordPress sanitization if available.
		if ( function_exists( 'sanitize_text_field' ) ) {
			$patterns = array_map( 'sanitize_text_field', $patterns );
		}

		// Remove duplicates.
		$patterns = array_unique( $patterns );

		// Filter to valid patterns only.
		$patterns = self::filter_valid_patterns( $patterns );

		return $as_string ? implode( "\n", $patterns ) : $patterns;
	}

}