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
	 *
	 * @var string[]
	 */
	protected static array $ip_headers = [
		'HTTP_CF_CONNECTING_IP',    // Cloudflare
		'HTTP_X_REAL_IP',           // Nginx proxy
		'HTTP_CLIENT_IP',           // Common proxy
		'HTTP_X_FORWARDED_FOR',     // Common proxy
		'REMOTE_ADDR',              // Direct connection
	];

	/**
	 * Get the current user's IP address.
	 *
	 * Attempts to determine the actual client IP address by checking various HTTP headers,
	 * taking into account proxy servers and CDN configurations.
	 *
	 * @return string|null The user's IP address, or null if not found/invalid.
	 */
	public static function get(): ?string {
		foreach ( self::$ip_headers as $header ) {
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
	 * Check if an IP address matches any in a list of IPs or IP ranges.
	 *
	 * @param string $ip      The IP address to check.
	 * @param array  $ip_list List of IPs or IP ranges to check against.
	 *
	 * @return bool Whether the IP address matches any in the list.
	 */
	public static function is_match( string $ip, array $ip_list ): bool {
		$ip = trim( $ip );
		if ( empty( $ip ) || ! self::is_valid( $ip ) ) {
			return false;
		}

		foreach ( $ip_list as $list_ip ) {
			$list_ip = trim( $list_ip );

			if ( str_contains( $list_ip, '/' ) && self::is_valid_range( $list_ip ) ) {
				if ( self::is_in_range( $ip, $list_ip ) ) {
					return true;
				}
			} elseif ( $list_ip === $ip ) {
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

}