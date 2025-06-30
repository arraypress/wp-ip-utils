<?php
/**
 * IPs Utility Class
 *
 * Provides utility functions for working with multiple IP addresses,
 * including bulk validation, filtering, anonymization, and analysis operations.
 *
 * @package ArrayPress\IPUtils
 * @since   1.0.0
 * @author  ArrayPress
 * @license GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace ArrayPress\IPUtils;

/**
 * IPs Class
 *
 * Bulk operations for working with multiple IP addresses.
 */
class IPs {

	/**
	 * Validate multiple IP addresses.
	 *
	 * @param array $ips Array of IP addresses to validate.
	 *
	 * @return array Array with IPs as keys and validation results as values.
	 */
	public static function validate( array $ips ): array {
		$results = [];
		foreach ( $ips as $ip ) {
			$ip             = trim( $ip );
			$results[ $ip ] = IP::is_valid( $ip );
		}

		return $results;
	}

	/**
	 * Filter and return only valid IP addresses.
	 *
	 * @param array $ips Array of IP addresses to filter.
	 *
	 * @return array Array of valid IP addresses.
	 */
	public static function filter( array $ips ): array {
		$valid = [];
		foreach ( $ips as $ip ) {
			$ip = trim( $ip );
			if ( IP::is_valid( $ip ) ) {
				$valid[] = $ip;
			}
		}

		return $valid;
	}

	/**
	 * Filter and return only invalid IP addresses.
	 *
	 * @param array $ips Array of IP addresses to filter.
	 *
	 * @return array Array of invalid IP addresses.
	 */
	public static function invalid( array $ips ): array {
		$invalid = [];
		foreach ( $ips as $ip ) {
			$ip = trim( $ip );
			if ( ! IP::is_valid( $ip ) ) {
				$invalid[] = $ip;
			}
		}

		return $invalid;
	}

	/**
	 * Anonymize multiple IP addresses.
	 *
	 * @param array $ips Array of IP addresses to anonymize.
	 *
	 * @return array Array of anonymized IP addresses.
	 */
	public static function anonymize( array $ips ): array {
		$anonymized = [];
		foreach ( $ips as $ip ) {
			$result = IP::anonymize( $ip );
			if ( $result !== null ) {
				$anonymized[] = $result;
			}
		}

		return $anonymized;
	}

	/**
	 * Mask multiple IP addresses.
	 *
	 * @param array $ips Array of IP addresses to mask.
	 *
	 * @return array Array of masked IP addresses.
	 */
	public static function mask( array $ips ): array {
		$masked = [];
		foreach ( $ips as $ip ) {
			$result = IP::mask_last_octet( $ip );
			if ( $result !== null ) {
				$masked[] = $result;
			}
		}

		return $masked;
	}

	/**
	 * Extract all IP addresses from text.
	 *
	 * @param string $text Text to extract IP addresses from.
	 *
	 * @return array Array of extracted IP addresses.
	 */
	public static function extract( string $text ): array {
		// Include IP-specific characters: dots, colons (IPv6), numbers, and hex chars
		$words = str_word_count( $text, 1, '.:0123456789abcdefABCDEF' );
		$ips   = array_filter( $words, [ IP::class, 'is_valid' ] );

		// Remove duplicates and reindex
		return array_values( array_unique( $ips ) );
	}

	/**
	 * Remove duplicate IP addresses from an array.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Array of unique IP addresses.
	 */
	public static function remove_duplicates( array $ips ): array {
		$unique = [];
		foreach ( $ips as $ip ) {
			$ip = trim( $ip );
			if ( IP::is_valid( $ip ) && ! in_array( $ip, $unique, true ) ) {
				$unique[] = $ip;
			}
		}

		return $unique;
	}

	/**
	 * Filter IPs by type (IPv4 or IPv6).
	 *
	 * @param array  $ips  Array of IP addresses.
	 * @param string $type Type to filter ('ipv4' or 'ipv6').
	 *
	 * @return array Filtered IP addresses.
	 */
	public static function filter_by_type( array $ips, string $type ): array {
		$filtered = [];

		foreach ( $ips as $ip ) {
			$include = false;

			switch ( strtolower( $type ) ) {
				case 'ipv4':
					$include = IP::is_valid_ipv4( $ip );
					break;
				case 'ipv6':
					$include = IP::is_valid_ipv6( $ip );
					break;
			}

			if ( $include ) {
				$filtered[] = $ip;
			}
		}

		return $filtered;
	}

	/**
	 * Filter IPs by privacy status.
	 *
	 * @param array  $ips  Array of IP addresses.
	 * @param string $type Type to filter ('private' or 'public').
	 *
	 * @return array Filtered IP addresses.
	 */
	public static function filter_by_privacy( array $ips, string $type ): array {
		$filtered = [];

		foreach ( $ips as $ip ) {
			$include = false;

			switch ( strtolower( $type ) ) {
				case 'private':
					$include = IP::is_private( $ip );
					break;
				case 'public':
					$include = IP::is_public( $ip );
					break;
			}

			if ( $include ) {
				$filtered[] = $ip;
			}
		}

		return $filtered;
	}

	/**
	 * Get only IPv4 addresses.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Array of IPv4 addresses.
	 */
	public static function filter_ipv4( array $ips ): array {
		return self::filter_by_type( $ips, 'ipv4' );
	}

	/**
	 * Get only IPv6 addresses.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Array of IPv6 addresses.
	 */
	public static function filter_ipv6( array $ips ): array {
		return self::filter_by_type( $ips, 'ipv6' );
	}

	/**
	 * Get only private IP addresses.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Array of private IP addresses.
	 */
	public static function filter_private( array $ips ): array {
		return self::filter_by_privacy( $ips, 'private' );
	}

	/**
	 * Get only public IP addresses.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Array of public IP addresses.
	 */
	public static function filter_public( array $ips ): array {
		return self::filter_by_privacy( $ips, 'public' );
	}

	/**
	 * Filter IP addresses by CIDR range.
	 *
	 * @param array  $ips     Array of IP addresses.
	 * @param string $range   CIDR range to filter by.
	 * @param bool   $include Whether to include (true) or exclude (false) matches.
	 *
	 * @return array Filtered IP addresses.
	 */
	public static function filter_by_range( array $ips, string $range, bool $include = true ): array {
		$filtered = [];

		foreach ( $ips as $ip ) {
			$in_range = IP::is_in_range( $ip, $range );
			if ( ( $include && $in_range ) || ( ! $include && ! $in_range ) ) {
				$filtered[] = $ip;
			}
		}

		return $filtered;
	}

	/**
	 * Filter IP addresses by multiple CIDR ranges.
	 *
	 * @param array $ips     Array of IP addresses.
	 * @param array $ranges  Array of CIDR ranges.
	 * @param bool  $include Whether to include (true) or exclude (false) matches.
	 *
	 * @return array Filtered IP addresses.
	 */
	public static function filter_by_ranges( array $ips, array $ranges, bool $include = true ): array {
		$filtered = [];

		foreach ( $ips as $ip ) {
			$matches = IP::is_match( $ip, $ranges );
			if ( ( $include && $matches ) || ( ! $include && ! $matches ) ) {
				$filtered[] = $ip;
			}
		}

		return $filtered;
	}

	/**
	 * Group IP addresses by CIDR ranges.
	 *
	 * @param array $ips    Array of IP addresses.
	 * @param array $ranges Array of CIDR ranges with labels.
	 *
	 * @return array Array with range labels as keys and IP arrays as values.
	 */
	public static function group_by_ranges( array $ips, array $ranges ): array {
		$groups = [];

		// Initialize groups
		foreach ( $ranges as $label => $range ) {
			$groups[ $label ] = [];
		}
		$groups['other'] = [];

		foreach ( $ips as $ip ) {
			$matched = false;

			foreach ( $ranges as $label => $range ) {
				if ( IP::is_in_range( $ip, $range ) ) {
					$groups[ $label ][] = $ip;
					$matched            = true;
					break;
				}
			}

			if ( ! $matched ) {
				$groups['other'][] = $ip;
			}
		}

		return $groups;
	}

	/**
	 * Convert multiple IP addresses to decimal.
	 *
	 * @param array $ips Array of IP addresses to convert.
	 *
	 * @return array Array with IPs as keys and decimals as values.
	 */
	public static function to_decimal( array $ips ): array {
		$decimals = [];

		foreach ( $ips as $ip ) {
			$decimal = IP::to_decimal( $ip );
			if ( ! empty( $decimal ) ) {
				$decimals[ $ip ] = $decimal;
			}
		}

		return $decimals;
	}

	/**
	 * Check if any IP in the array is anonymized.
	 *
	 * @param array $ips Array of IP addresses to check.
	 *
	 * @return array Array with IPs as keys and anonymized status as values.
	 */
	public static function check_anonymized( array $ips ): array {
		$results = [];

		foreach ( $ips as $ip ) {
			$results[ $ip ] = IP::is_anonymized( $ip );
		}

		return $results;
	}

	/**
	 * Get statistics for an array of IP addresses.
	 *
	 * @param array $ips Array of IP addresses.
	 *
	 * @return array Statistics including counts, percentages, and breakdowns.
	 */
	public static function get_statistics( array $ips ): array {
		$total       = count( $ips );
		$valid       = self::filter( $ips );
		$valid_count = count( $valid );

		if ( $valid_count === 0 ) {
			return [
				'total'         => $total,
				'valid'         => 0,
				'invalid'       => $total,
				'valid_percent' => 0
			];
		}

		$ipv4_count       = count( self::filter_ipv4( $valid ) );
		$ipv6_count       = count( self::filter_ipv6( $valid ) );
		$private_count    = count( self::filter_private( $valid ) );
		$public_count     = count( self::filter_public( $valid ) );
		$anonymized_count = count( array_filter( self::check_anonymized( $valid ) ) );

		return [
			'total'            => $total,
			'valid'            => $valid_count,
			'invalid'          => $total - $valid_count,
			'valid_percent'    => round( ( $valid_count / $total ) * 100, 2 ),
			'ipv4_count'       => $ipv4_count,
			'ipv6_count'       => $ipv6_count,
			'ipv4_percent'     => round( ( $ipv4_count / $valid_count ) * 100, 2 ),
			'ipv6_percent'     => round( ( $ipv6_count / $valid_count ) * 100, 2 ),
			'private_count'    => $private_count,
			'public_count'     => $public_count,
			'private_percent'  => round( ( $private_count / $valid_count ) * 100, 2 ),
			'public_percent'   => round( ( $public_count / $valid_count ) * 100, 2 ),
			'anonymized_count' => $anonymized_count,
			'unique_count'     => count( self::remove_duplicates( $valid ) )
		];
	}

	/**
	 * Clean and sanitize an array of IP addresses.
	 *
	 * @param array $ips               Array of IP addresses to clean.
	 * @param bool  $remove_private    Whether to remove private IP addresses.
	 * @param bool  $remove_duplicates Whether to remove duplicate IPs.
	 *
	 * @return array Clean array of IP addresses.
	 */
	public static function clean( array $ips, bool $remove_private = false, bool $remove_duplicates = true ): array {
		// Remove invalid IPs
		$valid = self::filter( $ips );

		// Remove private IPs if requested
		if ( $remove_private ) {
			$valid = self::filter_public( $valid );
		}

		// Remove duplicates if requested
		if ( $remove_duplicates ) {
			$valid = self::remove_duplicates( $valid );
		}

		return $valid;
	}

}