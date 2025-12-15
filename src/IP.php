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
	 * Headers that might contain the real user's IP address, in order of priority.
	 */
	private const IP_HEADERS = [
		'HTTP_CF_CONNECTING_IP',    // Cloudflare
		'HTTP_X_REAL_IP',           // Nginx proxy
		'HTTP_CLIENT_IP',           // Common proxy
		'HTTP_X_FORWARDED_FOR',     // Common proxy
		'REMOTE_ADDR',              // Direct connection
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
	 * Attempts to determine the actual client IP address by checking various HTTP headers,
	 * taking into account proxy servers and CDN configurations.
	 *
	 * @return string|null The user's IP address, or null if not found/invalid.
	 */
	public static function get(): ?string {
		foreach ( self::IP_HEADERS as $header ) {
			if ( empty( $_SERVER[ $header ] ) ) {
				continue;
			}

			$ip = $_SERVER[ $header ];
			if ( $header === 'HTTP_X_FORWARDED_FOR' ) {
				$ips = explode( ',', $ip );
				$ip  = trim( $ips[0] );
			}

			if ( self::is_valid( $ip ) && ! self::is_private( $ip ) ) {
				return $ip;
			}
		}

		return null;
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

		if ( self::is_valid_ipv4( $ip ) ) {
			return self::is_ipv4_in_range( $ip, $subnet, $bits );
		}

		if ( self::is_valid_ipv6( $ip ) ) {
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

		// Create mask
		$mask      = str_repeat( "\xFF", $bits >> 3 );
		$remainder = $bits & 7;
		if ( $remainder ) {
			$mask .= chr( 0xFF << ( 8 - $remainder ) );
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