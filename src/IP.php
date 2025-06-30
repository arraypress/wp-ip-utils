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
	 * Check if an IP address is public.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool True if the IP is public.
	 */
	public static function is_public( string $ip ): bool {
		return self::is_valid( $ip ) && ! self::is_private( $ip );
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

	/**
	 * Mask the last octet of an IPv4 address or last group of IPv6.
	 *
	 * @param string $ip The IP address to mask.
	 *
	 * @return string|null The masked IP address, or null if invalid.
	 */
	public static function mask_last_octet( string $ip ): ?string {
		if ( ! self::is_valid( $ip ) ) {
			return null;
		}

		if ( self::is_valid_ipv4( $ip ) ) {
			return preg_replace( '/\.\d+$/', '.***', $ip );
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			return preg_replace( '/:[^:]*$/', ':****', $ip );
		}

		return null;
	}

	/**
	 * Check if an IP address is already anonymized.
	 *
	 * @param string $ip The IP address to check.
	 *
	 * @return bool True if the IP appears to be anonymized, false otherwise.
	 */
	public static function is_anonymized( string $ip ): bool {
		// Check for masked IPs (with asterisks)
		if ( str_contains( $ip, '*' ) ) {
			return true;
		}

		// Special case for IPv6 all-zeros
		if ( $ip === '::' ) {
			return true;
		}

		// Only check valid IPs to avoid false positives
		if ( ! self::is_valid( $ip ) ) {
			return false;
		}

		// Check for anonymized patterns only on valid IPs
		if ( self::is_valid_ipv4( $ip ) && preg_match( '/\.0$/', $ip ) ) {
			return true;
		}

		if ( self::is_valid_ipv6( $ip ) && preg_match( '/:0$/', $ip ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Convert an IP address to its decimal representation.
	 *
	 * @param string $ip The IP address to convert.
	 *
	 * @return string The decimal representation of the IP, or empty string on failure.
	 */
	public static function to_decimal( string $ip ): string {
		if ( self::is_valid_ipv4( $ip ) ) {
			return (string) ip2long( $ip );
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			$binary = inet_pton( $ip );
			$hex    = unpack( 'H*hex', $binary )['hex'];
			$dec    = '0';
			for ( $i = 0; $i < strlen( $hex ); $i ++ ) {
				$dec = bcadd( bcmul( $dec, '16' ), (string) hexdec( $hex[ $i ] ) );
			}

			return $dec;
		}

		return '';
	}

	/**
	 * Convert a decimal representation back to an IP address.
	 *
	 * @param string $decimal The decimal representation of an IP.
	 * @param bool   $is_ipv6 Whether the decimal represents an IPv6 address.
	 *
	 * @return string The IP address, or empty string on failure.
	 */
	public static function from_decimal( string $decimal, bool $is_ipv6 = false ): string {
		if ( $is_ipv6 ) {
			$hex = '';
			while ( bccomp( $decimal, '0' ) > 0 ) {
				$hex     = dechex( (int) bcmod( $decimal, '16' ) ) . $hex;
				$decimal = bcdiv( $decimal, '16', 0 );
			}
			$hex    = str_pad( $hex, 32, '0', STR_PAD_LEFT );
			$binary = pack( 'H*', $hex );

			return inet_ntop( $binary ) ?: '';
		}

		return long2ip( (int) $decimal ) ?: '';
	}

	/**
	 * Get the network address of a CIDR range.
	 *
	 * @param string $cidr The CIDR range.
	 *
	 * @return string The network address, or empty string on failure.
	 */
	public static function get_network_address( string $cidr ): string {
		$parts = explode( '/', $cidr );
		if ( count( $parts ) !== 2 ) {
			return '';
		}

		[ $ip, $prefix ] = $parts;
		$prefix = (int) $prefix;

		if ( self::is_valid_ipv4( $ip ) ) {
			$mask = - 1 << ( 32 - $prefix );

			return long2ip( ip2long( $ip ) & $mask ) ?: '';
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			$mask    = self::create_ipv6_mask( $prefix );
			$network = inet_pton( $ip ) & $mask;

			return inet_ntop( $network ) ?: '';
		}

		return '';
	}

	/**
	 * Get the broadcast address of a CIDR range (IPv4 only).
	 *
	 * @param string $cidr The CIDR range.
	 *
	 * @return string The broadcast address, or empty string on failure.
	 */
	public static function get_broadcast_address( string $cidr ): string {
		[ $ip, $prefix ] = explode( '/', $cidr );
		if ( self::is_valid_ipv4( $ip ) ) {
			$mask      = - 1 << ( 32 - (int) $prefix );
			$broadcast = ip2long( $ip ) | ~$mask;

			return long2ip( $broadcast ) ?: '';
		}

		return '';  // IPv6 doesn't use broadcast addresses
	}

	/**
	 * Calculate the number of available IP addresses in a CIDR range.
	 *
	 * @param string $cidr The CIDR range.
	 *
	 * @return int The number of available IP addresses, or 0 on failure.
	 */
	public static function get_address_count( string $cidr ): int {
		$parts = explode( '/', $cidr );
		if ( count( $parts ) !== 2 ) {
			return 0;
		}

		[ $ip, $prefix ] = $parts;
		$prefix = (int) $prefix;

		if ( self::is_valid_ipv4( $ip ) ) {
			return max( 0, pow( 2, 32 - $prefix ) - 2 );  // Subtract network and broadcast addresses
		}

		if ( self::is_valid_ipv6( $ip ) ) {
			if ( $prefix >= 64 ) {
				return min( PHP_INT_MAX, pow( 2, 128 - $prefix ) );
			}

			return PHP_INT_MAX; // For very large ranges
		}

		return 0;
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
		$mask_bin   = self::create_ipv6_mask( $bits );

		return ( ( $ip_bin & $mask_bin ) === ( $subnet_bin & $mask_bin ) );
	}

	/**
	 * Creates an IPv6 mask based on the number of network bits.
	 *
	 * @param int $bits The number of network bits.
	 *
	 * @return string Binary representation of the IPv6 mask.
	 */
	private static function create_ipv6_mask( int $bits ): string {
		$mask = str_repeat( "\xFF", $bits >> 3 );
		$bits &= 7;
		if ( $bits ) {
			$mask .= chr( 0xFF << ( 8 - $bits ) );
		}

		return str_pad( $mask, 16, "\x00" );
	}

}