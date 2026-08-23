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
	 * @param bool $allow_private Return private, loopback and reserved
	 *                            addresses instead of null. For audit
	 *                            logs and intranet deployments, where
	 *                            "logged in from 192.168.1.50" is useful
	 *                            data. The trusted-proxy rule still
	 *                            applies — this loosens which addresses
	 *                            are acceptable, never which sources are
	 *                            believed.
	 *
	 * @return string|null The user's IP address, or null if not found/invalid.
	 * @since  1.1.0 Forwarding headers now require a trusted proxy.
	 * @since  1.1.1 Added $allow_private.
	 */
	public static function get( bool $allow_private = false ): ?string {
		$remote = self::server( 'REMOTE_ADDR' );
		$remote = self::is_valid( $remote ) ? $remote : null;

		if ( null !== $remote && self::is_trusted_proxy( $remote ) ) {
			foreach ( self::FORWARDED_HEADERS as $header ) {
				$value = self::server( $header );

				if ( '' === $value ) {
					continue;
				}

				$found = self::from_forwarded( $value, $allow_private );

				if ( null !== $found ) {
					return $found;
				}
			}
		}

		if ( null === $remote ) {
			return null;
		}

		return ( $allow_private || ! self::is_private( $remote ) ) ? $remote : null;
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
	 * @param string $value         Raw header value.
	 * @param bool   $allow_private Accept a private client address.
	 *
	 * @return string|null Client address, or null if none usable.
	 * @since  1.1.0
	 */
	private static function from_forwarded( string $value, bool $allow_private = false ): ?string {
		$parts    = array_reverse( array_map( 'trim', explode( ',', $value ) ) );
		$furthest = null;

		foreach ( $parts as $candidate ) {
			$candidate = self::strip_port( $candidate );

			if ( ! self::is_valid( $candidate ) ) {
				continue;
			}

			// Remember the client-most valid entry as we go, for the
			// permissive fallback below.
			$furthest = $candidate;

			// Skip our own infrastructure to reach the real client.
			if ( self::is_trusted_proxy( $candidate ) ) {
				continue;
			}

			return ( $allow_private || ! self::is_private( $candidate ) ) ? $candidate : null;
		}

		// Every entry looked like one of our proxies. On an intranet that
		// is expected rather than suspicious: the trusted list contains
		// RFC 1918 by default, and the client is on RFC 1918 too, so the
		// real visitor gets skipped as infrastructure. In permissive mode
		// fall back to the client-most entry.
		//
		// This is deliberately NOT done in strict mode. The leftmost
		// entry is the part of the header a client can pre-seed, so it is
		// advisory information for an audit log, never a security
		// boundary. Configure ARRAYPRESS_TRUSTED_PROXIES with your actual
		// proxy addresses if you need this to be authoritative.
		return $allow_private ? $furthest : null;
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

		$country = strtoupper( substr( self::server( self::CF_COUNTRY_HEADER ), 0, 2 ) );

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
		return 'T1' === self::server( self::CF_COUNTRY_HEADER );
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
		$ray = self::server( self::CF_RAY_HEADER );

		return '' !== $ray ? $ray : null;
	}

	/**
	 * Read a $_SERVER value, unslashed.
	 *
	 * WordPress runs add_magic_quotes() over $_SERVER as well as the request
	 * superglobals, so a header containing a quote arrives with a backslash in
	 * front of it. Reading these raw is why every caller here looked like an
	 * unsanitised input to the coding standards -- and, less cosmetically, why
	 * a quoted user agent or forwarded header would not compare equal to
	 * itself.
	 *
	 * Falls back to the raw value outside WordPress, where nothing added the
	 * slashes in the first place.
	 *
	 * @param string $key The $_SERVER key.
	 *
	 * @return string The unslashed value, or an empty string.
	 *
	 * @since 1.2.0
	 */
	private static function server( string $key ): string {
		if ( ! isset( $_SERVER[ $key ] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- both happen below, conditionally, because this library also runs without WordPress.
		$value = $_SERVER[ $key ];

		if ( function_exists( 'wp_unslash' ) ) {
			$value = wp_unslash( $value );
		}

		$value = is_scalar( $value ) ? (string) $value : '';

		return function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $value ) : trim( $value );
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
	 * - Wildcard: 192.168.*.* or 2001:db8:*
	 *
	 * Wildcards count because is_match() matches them. Leaving them out here
	 * meant sanitize_pattern_list() stripped exactly the rules matching
	 * supports, so a saved list quietly lost every wildcard in it.
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

		// Wildcard pattern.
		if ( str_contains( $pattern, '*' ) ) {
			return self::is_valid_wildcard( $pattern );
		}

		return false;
	}

	/**
	 * Check whether a wildcard pattern is one that could ever be meant.
	 *
	 * A pattern of nothing but wildcards and separators matches every address
	 * in its family, which nobody types into a list on purpose -- and in an
	 * allowlist it is indistinguishable from having no restriction at all.
	 * Accepting it as "valid" would let it through a sanitiser unremarked.
	 *
	 * @param string $pattern The pattern to validate.
	 *
	 * @return bool True if the pattern has at least one literal part.
	 *
	 * @since 1.2.0
	 */
	public static function is_valid_wildcard( string $pattern ): bool {
		$pattern = trim( $pattern );

		if ( ! str_contains( $pattern, '*' ) ) {
			return false;
		}

		// Only the characters an address is written with, plus the wildcard.
		if ( 1 !== preg_match( '/^[0-9a-fA-F.:*]+$/', $pattern ) ) {
			return false;
		}

		// At least one part has to be a literal.
		return '' !== trim( str_replace( array( '*', '.', ':' ), '', $pattern ) );
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
